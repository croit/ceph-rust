// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Format `qcow` (v1, v2 and v3): header parsing, the common L1/L2 lookup
//! math, the snapshot walk, the read path and the per-revision sparse
//! delta.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`, "Format
//! `qcow`". All header, table and snapshot parsing happens during open, so
//! every structural error is a prepare error. There is no refcount-table,
//! overlap or consistency validation: an inconsistent container is read as
//! its L1/L2 tables say.

use std::collections::HashMap;

use serde_json::Value;

use crate::journal_backend::{EINVAL, ENOENT, ERANGE};
use crate::migration_source::{
    CEPH_NOSNAP, ENOMEM, ENOSYS, ENOTSUP, RevisionDelta, SourceSnapshot, SourceStream,
    SourceTimestamp, build_stream, delta_extents, extent_total, intersect, merge_intervals,
    requested_positions, uuid_string, zero_buffer,
};
use crate::snapshot_query::SnapshotNamespace;

/// The qcow magic: `Q` `F` `I` 0xfb.
const MAGIC: u32 = 0x5146_49fb;
/// The v1 header length.
const V1_HEADER: u64 = 48;
/// The v2/v3 header length: always read in full, even for v2.
const V23_HEADER: u64 = 112;
/// One qcow snapshot header.
const SNAP_HEADER: u64 = 40;
/// The L1 entries a table may hold (INT32_MAX / 8).
const L1_MAX_ENTRIES: u64 = 268_435_455;
/// The v2/v3 entry mask: clears bits 62 and 63.
const MASK_V23: u64 = 0x3fff_ffff_ffff_ffff;
/// The v1 entry mask: clears bit 62 only.
const MASK_V1: u64 = 0xbfff_ffff_ffff_ffff;
/// The compressed-cluster flag: bit 62 for v2/v3.
const COMPRESS_V23: u64 = 1 << 62;
/// The compressed-cluster flag: bit 63 for v1.
const COMPRESS_V1: u64 = 1 << 63;

#[derive(Debug)]
struct Revision {
    id: u64,
    name: String,
    size: u64,
    timestamp: SourceTimestamp,
    l1: Vec<u64>,
}

#[derive(Debug)]
pub(crate) struct QcowSource {
    stream: Box<dyn SourceStream>,
    cluster_size: u64,
    l2_size: u64,
    l1_shift: u32,
    entry_mask: u64,
    compress_bit: u64,
    l1_mask: Option<u64>,
    head: Revision,
    snaps: Vec<Revision>,
}

impl QcowSource {
    /// Open order: build and open the stream, read 8 bytes at offset 0,
    /// parse magic and version, then the version's header.
    pub(crate) fn open(root: &Value) -> Result<Self, i32> {
        let ty = root.get("type").and_then(Value::as_str).ok_or(EINVAL)?;
        if ty != "qcow" {
            return Err(ENOSYS);
        }
        let mut stream = build_stream(root)?;
        stream.open()?;
        let mut head = [0u8; 8];
        stream.read(&[(0, 8)], &mut head)?;
        let magic = be32(&head[0..4]);
        let version = be32(&head[4..8]);
        if magic != MAGIC {
            return Err(EINVAL);
        }
        match version {
            1 => open_v1(stream),
            2 | 3 => open_v23(stream, version == 3),
            _ => Err(EINVAL),
        }
    }

    pub(crate) fn snapshots(&self) -> Vec<SourceSnapshot> {
        self.snaps
            .iter()
            .map(|revision| SourceSnapshot {
                id: revision.id,
                name: revision.name.clone(),
                size: revision.size,
                namespace: SnapshotNamespace::User,
                timestamp: revision.timestamp,
            })
            .collect()
    }

    fn revision(&self, snap_id: u64) -> Option<&Revision> {
        if snap_id == CEPH_NOSNAP {
            Some(&self.head)
        } else {
            self.snaps.iter().find(|revision| revision.id == snap_id)
        }
    }

    pub(crate) fn image_size(&self, snap_id: u64) -> Result<u64, i32> {
        self.revision(snap_id)
            .map(|revision| revision.size)
            .ok_or(ENOENT)
    }

    /// Reads are not clamped to the revision size; the caller must stay
    /// inside it.
    pub(crate) fn read(&self, snap_id: u64, extents: &[(u64, u64)]) -> Result<Vec<u8>, i32> {
        let revision = self.revision(snap_id).ok_or(ENOENT)?;
        let total = extent_total(extents)?;
        let mut out = zero_buffer(total)?;
        self.read_clusters(revision, extents, &mut out)?;
        Ok(out)
    }

    /// Each requested revision is compared with the previous requested
    /// one (the empty baseline for the first), cluster by cluster: an
    /// equal masked entry is no output, a dropped entry or an explicit
    /// zero cluster is ZEROED, the rest DATA. The shrink tail between the
    /// previous requested size and its own is ZEROED.
    pub(crate) fn list_snaps(
        &self,
        extents: &[(u64, u64)],
        snap_ids: &[u64],
    ) -> Result<Vec<RevisionDelta>, i32> {
        let region = merge_intervals(extents);
        if region.is_empty() {
            return Ok(Vec::new());
        }
        let mut chain: Vec<&Revision> = self.snaps.iter().collect();
        chain.push(&self.head);
        let chain_ids: Vec<u64> = chain.iter().map(|revision| revision.id).collect();
        let positions = requested_positions(&chain_ids, snap_ids)?;

        // Clusters beyond the largest L1-covered range of the requested
        // revisions have no entry in any of them; clipping the region
        // there also keeps the cluster walk overflow-safe at u64::MAX.
        let max_addr = positions
            .iter()
            .map(|&pos| {
                (chain[pos].l1.len() as u64)
                    .checked_shl(self.l1_shift)
                    .unwrap_or(u64::MAX)
            })
            .max()
            .unwrap_or(0);
        let cluster_region = intersect(&region, &[(0, max_addr)]);

        // The clusters covering the clipped region, ascending.
        let mut capacity = 0usize;
        for &(start, end) in &cluster_region {
            capacity = capacity
                .checked_add(((end - start) / self.cluster_size) as usize + 1)
                .ok_or(ENOMEM)?;
        }
        let mut clusters: Vec<u64> = Vec::new();
        clusters.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        for &(start, end) in &cluster_region {
            let first = start & !(self.cluster_size - 1);
            let last = (end - 1) & !(self.cluster_size - 1);
            let mut cursor = first;
            while cursor <= last {
                clusters.push(cursor);
                cursor += self.cluster_size;
            }
        }

        // The masked L2 entry of every requested cluster per requested
        // revision; an absent L1 index or entry is 0.
        let mut caches: Vec<HashMap<u64, Vec<u64>>> =
            (0..positions.len()).map(|_| HashMap::new()).collect();
        let mut entries: Vec<Vec<u64>> = Vec::with_capacity(positions.len());
        for &pos in &positions {
            let mut row = Vec::new();
            row.try_reserve_exact(clusters.len()).map_err(|_| ENOMEM)?;
            for &cluster in &clusters {
                row.push(self.entry(chain[pos], cluster, &mut caches[entries.len()])?);
            }
            entries.push(row);
        }

        let mut deltas = Vec::with_capacity(positions.len());
        for (k, &pos) in positions.iter().enumerate() {
            let mut data: Vec<(u64, u64)> = Vec::new();
            let mut zeroed: Vec<(u64, u64)> = Vec::new();
            for (c, &masked) in entries[k].iter().enumerate() {
                let before = if k > 0 { entries[k - 1][c] } else { 0 };
                if masked == before {
                    continue;
                }
                let cluster = clusters[c];
                let interval = (cluster, cluster + self.cluster_size);
                if (before != 0 && masked == 0) || masked == 1 {
                    zeroed.push(interval);
                } else {
                    data.push(interval);
                }
            }
            // The shrink tail is relative to the previous requested
            // revision.
            if k > 0 {
                let size = chain[pos].size;
                let prev_size = chain[positions[k - 1]].size;
                if size < prev_size {
                    zeroed.push((size, prev_size));
                }
            }
            let clip = intersect(&region, &[(0, chain[pos].size)]);
            deltas.push(RevisionDelta {
                snap_id: chain[pos].id,
                extents: delta_extents(
                    &intersect(&merge_intervals(&data), &clip),
                    &intersect(&merge_intervals(&zeroed), &region),
                ),
            });
        }
        Ok(deltas)
    }

    /// The masked L2 entry of one cluster for `list_snaps`; 0 when the L1
    /// index or entry is absent.
    fn entry(
        &self,
        revision: &Revision,
        cluster: u64,
        cache: &mut HashMap<u64, Vec<u64>>,
    ) -> Result<u64, i32> {
        let raw = match revision.l1.get((cluster >> self.l1_shift) as usize) {
            Some(raw) => raw,
            None => return Ok(0),
        };
        let offset = match self.l1_mask {
            Some(mask) => raw & mask,
            None => *raw,
        };
        if offset == 0 {
            return Ok(0);
        }
        let table = match cache.get(&offset) {
            Some(table) => table,
            None => {
                let length = (self.l2_size as usize).checked_mul(8).ok_or(ENOMEM)?;
                let mut bytes = zero_buffer(length)?;
                self.stream
                    .read(&[(offset, bytes.len() as u64)], &mut bytes)?;
                cache.entry(offset).or_insert_with(|| bytes_to_u64s(bytes))
            }
        };
        let index = ((cluster / self.cluster_size) % self.l2_size) as usize;
        Ok(table[index] & self.entry_mask)
    }

    /// Split the extents at cluster boundaries and resolve every cluster.
    fn read_clusters(
        &self,
        revision: &Revision,
        extents: &[(u64, u64)],
        out: &mut [u8],
    ) -> Result<(), i32> {
        let mut capacity = 0usize;
        for &(_, length) in extents {
            if length > 0 {
                capacity = capacity
                    .checked_add((length / self.cluster_size) as usize + 1)
                    .ok_or(ENOMEM)?;
            }
        }
        let mut clusters: Vec<(u64, u64, usize)> = Vec::new(); // (start, chunk, out position)
        clusters.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        let mut position = 0usize;
        for &(offset, length) in extents {
            let (mut cursor, mut remaining) = (offset, length);
            while remaining > 0 {
                let intra = cursor & (self.cluster_size - 1);
                let chunk = remaining.min(self.cluster_size - intra);
                clusters.push((cursor & !(self.cluster_size - 1), chunk, position));
                cursor += chunk;
                remaining -= chunk;
                position += chunk as usize;
            }
        }
        if clusters.is_empty() {
            return Ok(());
        }

        // The L2 tables of the allocated clusters, one stream read each
        // level.
        let mut l2_offsets: Vec<u64> = Vec::new();
        for &(cluster, _, _) in &clusters {
            let offset = self.l2_table_offset(revision, cluster)?;
            if offset != 0 && !l2_offsets.contains(&offset) {
                l2_offsets.push(offset);
            }
        }
        l2_offsets.sort_unstable();
        let l2_length = l2_offsets
            .len()
            .checked_mul(self.l2_size as usize)
            .and_then(|length| length.checked_mul(8))
            .ok_or(ENOMEM)?;
        let mut l2_table = zero_buffer(l2_length)?;
        if !l2_offsets.is_empty() {
            let table_extents: Vec<(u64, u64)> = l2_offsets
                .iter()
                .map(|&offset| (offset, self.l2_size * 8))
                .collect();
            self.stream.read(&table_extents, &mut l2_table)?;
        }

        // 0 = zeroes, otherwise the data cluster offset.
        let mut plans: Vec<u64> = Vec::with_capacity(clusters.len());
        for &(cluster, _, _) in &clusters {
            let offset = self.l2_table_offset(revision, cluster)?;
            if offset == 0 {
                plans.push(0);
                continue;
            }
            let base = l2_offsets
                .binary_search(&offset)
                .expect("deduplicated offset")
                * self.l2_size as usize
                * 8;
            let index = ((cluster / self.cluster_size) % self.l2_size) as usize;
            let raw = u64::from_be_bytes(
                l2_table[base + index * 8..base + index * 8 + 8]
                    .try_into()
                    .expect("8 bytes"),
            );
            if raw & self.compress_bit != 0 {
                return Err(EINVAL);
            }
            let masked = raw & self.entry_mask;
            plans.push(if masked == 0 || masked == 1 {
                0
            } else {
                masked
            });
        }

        let mut data_offsets: Vec<u64> = plans
            .iter()
            .copied()
            .filter(|&offset| offset != 0)
            .collect();
        data_offsets.sort_unstable();
        data_offsets.dedup();
        let data_length = data_offsets
            .len()
            .checked_mul(self.cluster_size as usize)
            .ok_or(ENOMEM)?;
        let mut data = zero_buffer(data_length)?;
        if !data_offsets.is_empty() {
            let cluster_extents: Vec<(u64, u64)> = data_offsets
                .iter()
                .map(|&offset| (offset, self.cluster_size))
                .collect();
            self.stream.read(&cluster_extents, &mut data)?;
        }

        for (&(cluster, chunk, position), &offset) in clusters.iter().zip(plans.iter()) {
            if offset == 0 {
                continue;
            }
            let base = data_offsets
                .binary_search(&offset)
                .expect("deduplicated offset")
                * self.cluster_size as usize;
            let intra = (cluster & (self.cluster_size - 1)) as usize;
            let chunk = chunk as usize;
            out[position..position + chunk]
                .copy_from_slice(&data[base + intra..base + intra + chunk]);
        }
        Ok(())
    }

    /// The L2 table offset of one cluster, 0 when unallocated; `-ERANGE`
    /// when the L1 index is beyond the table.
    fn l2_table_offset(&self, revision: &Revision, cluster: u64) -> Result<u64, i32> {
        let raw = *revision
            .l1
            .get((cluster >> self.l1_shift) as usize)
            .ok_or(ERANGE)?;
        Ok(match self.l1_mask {
            Some(mask) => raw & mask,
            None => raw,
        })
    }

    pub(crate) fn close(&mut self) -> i32 {
        self.stream.close()
    }
}

/// The validated lookup geometry.
struct Geometry {
    cluster_size: u64,
    l2_size: u64,
    l1_shift: u32,
    l1_count: u64,
}

impl Geometry {
    /// `cluster_bits` in [9, 21] (checked by the caller) and the L1
    /// overflow guards: `-EINVAL` when the L1 table would not fit.
    fn new(cluster_bits: u8, l2_bits: u32, size: u64) -> Result<Self, i32> {
        let l1_shift = cluster_bits as u32 + l2_bits;
        let l1_stride = 1u64 << l1_shift;
        if size > u64::MAX - l1_stride {
            return Err(EINVAL);
        }
        let l1_count = size.div_ceil(l1_stride);
        if l1_count > L1_MAX_ENTRIES {
            return Err(EINVAL);
        }
        Ok(Self {
            cluster_size: 1 << cluster_bits,
            l2_size: 1 << l2_bits,
            l1_shift,
            l1_count,
        })
    }
}

/// The v1 header: 48 bytes at offset 0, big-endian.
fn open_v1(stream: Box<dyn SourceStream>) -> Result<QcowSource, i32> {
    let mut header = vec![0u8; V1_HEADER as usize];
    stream.read(&[(0, V1_HEADER)], &mut header)?;
    let size = be64(&header[24..32]);
    let cluster_bits = header[32];
    let l2_bits = header[33];
    let crypt_method = be32(&header[36..40]);
    let l1_table_offset = be64(&header[40..48]);

    if !(9..=21).contains(&cluster_bits) {
        return Err(EINVAL);
    }
    if !(6..=18).contains(&l2_bits) {
        return Err(EINVAL);
    }
    if crypt_method != 0 {
        return Err(EINVAL);
    }
    if !size.is_multiple_of(512) {
        return Err(EINVAL);
    }

    let geometry = Geometry::new(cluster_bits, l2_bits as u32, size)?;
    let l1 = read_l1(&*stream, l1_table_offset, None, geometry.l1_count)?;
    Ok(QcowSource {
        stream,
        cluster_size: geometry.cluster_size,
        l2_size: geometry.l2_size,
        l1_shift: geometry.l1_shift,
        entry_mask: MASK_V1,
        compress_bit: COMPRESS_V1,
        l1_mask: None,
        head: Revision {
            id: CEPH_NOSNAP,
            name: String::new(),
            size,
            timestamp: SourceTimestamp::default(),
            l1,
        },
        snaps: Vec::new(),
    })
}

/// The v2/v3 header: 112 bytes read at offset 0, big-endian; for version 2
/// the feature words, `header_length` and `compression_type` are forced
/// without using the file's bytes.
fn open_v23(stream: Box<dyn SourceStream>, v3: bool) -> Result<QcowSource, i32> {
    let mut header = vec![0u8; V23_HEADER as usize];
    stream.read(&[(0, V23_HEADER)], &mut header)?;
    let backing_file_offset = be64(&header[8..16]);
    let backing_file_size = be32(&header[16..20]);
    let cluster_bits = be32(&header[20..24]);
    let size = be64(&header[24..32]);
    let crypt_method = be32(&header[32..36]);
    let l1_size = be32(&header[36..40]);
    let l1_table_offset = be64(&header[40..48]);
    let nb_snapshots = be32(&header[60..64]);
    let snapshots_offset = be64(&header[64..72]);
    let mut incompatible = 0u64;
    let mut compression_type = 0u8;
    if v3 {
        incompatible = be64(&header[72..80]);
        if be32(&header[100..104]) > 104 {
            compression_type = header[104];
        }
    }

    if !(9..=21).contains(&cluster_bits) {
        return Err(EINVAL);
    }
    if crypt_method != 0 {
        return Err(EINVAL);
    }
    if !size.is_multiple_of(512) {
        return Err(EINVAL);
    }
    if compression_type != 0 || incompatible & (1 << 3) != 0 {
        return Err(EINVAL);
    }
    if incompatible & (1 << 2) != 0 {
        return Err(ENOTSUP);
    }
    if incompatible & (1 << 4) != 0 {
        return Err(ENOTSUP);
    }
    if incompatible & !0b111 != 0 {
        return Err(EINVAL);
    }

    let geometry = Geometry::new(cluster_bits as u8, cluster_bits - 3, size)?;
    if geometry.l1_count > l1_size as u64 {
        return Err(EINVAL);
    }

    // The snapshot walk, then the HEAD L1 read, then the backing-file check.
    let mut snaps: Vec<Revision> = Vec::new();
    if nb_snapshots > 0 && snapshots_offset != 0 {
        snaps
            .try_reserve_exact(nb_snapshots as usize)
            .map_err(|_| ENOMEM)?;
        let mut cursor = snapshots_offset;
        for id in 1..=nb_snapshots as u64 {
            cursor = cursor.saturating_add(7) & !7;
            let mut snap_header = [0u8; SNAP_HEADER as usize];
            stream.read(&[(cursor, SNAP_HEADER)], &mut snap_header)?;
            cursor = cursor.saturating_add(SNAP_HEADER);
            let snap_l1_offset = be64(&snap_header[0..8]);
            let snap_l1_size = be32(&snap_header[8..12]);
            let id_str_size = be16(&snap_header[12..14]) as u64;
            let name_size = be16(&snap_header[14..16]) as u64;
            let timestamp = SourceTimestamp {
                sec: be32(&snap_header[16..20]),
                nsec: be32(&snap_header[20..24]),
            };
            let extra_data_size = be32(&snap_header[36..40]) as u64;
            let payload = extra_data_size + id_str_size + name_size;
            let (snap_size, name) = if payload == 0 {
                // Quirk: no extra-data read and no L1 read; the size stays 0.
                (0, uuid_string())
            } else {
                let mut blob = zero_buffer(payload as usize)?;
                stream.read(&[(cursor, payload)], &mut blob)?;
                cursor = cursor.saturating_add(payload);
                let snap_size = if extra_data_size >= 16 {
                    be64(&blob[8..16])
                } else {
                    size
                };
                let name_start = (extra_data_size + id_str_size) as usize;
                let name =
                    String::from_utf8_lossy(&blob[name_start..name_start + name_size as usize])
                        .into_owned();
                (snap_size, name)
            };
            let name = if name.is_empty() { uuid_string() } else { name };
            let l1_count = (snap_l1_size as u64).min(snap_size.div_ceil(1 << geometry.l1_shift));
            let l1 = read_l1(&*stream, snap_l1_offset, Some(MASK_V23), l1_count)?;
            snaps.push(Revision {
                id,
                name,
                size: snap_size,
                timestamp,
                l1,
            });
        }
    }

    let l1 = read_l1(&*stream, l1_table_offset, Some(MASK_V23), geometry.l1_count)?;
    if backing_file_offset != 0 && backing_file_size != 0 {
        return Err(ENOTSUP);
    }

    Ok(QcowSource {
        stream,
        cluster_size: geometry.cluster_size,
        l2_size: geometry.l2_size,
        l1_shift: geometry.l1_shift,
        entry_mask: MASK_V23,
        compress_bit: COMPRESS_V23,
        l1_mask: Some(MASK_V23),
        head: Revision {
            id: CEPH_NOSNAP,
            name: String::new(),
            size,
            timestamp: SourceTimestamp::default(),
            l1,
        },
        snaps,
    })
}

/// Read one L1 table: `count * 8` bytes at the (masked) offset,
/// byte-swapped; an empty table reads nothing.
fn read_l1(
    stream: &dyn SourceStream,
    offset: u64,
    mask: Option<u64>,
    count: u64,
) -> Result<Vec<u64>, i32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let offset = match mask {
        Some(mask) => offset & mask,
        None => offset,
    };
    let length = (count as usize).checked_mul(8).ok_or(ENOMEM)?;
    let mut bytes = zero_buffer(length)?;
    stream.read(&[(offset, bytes.len() as u64)], &mut bytes)?;
    Ok(bytes_to_u64s(bytes))
}

fn bytes_to_u64s(bytes: Vec<u8>) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_be_bytes(*chunk))
        .collect()
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("4-byte slice"))
}

fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_source::{OpenError, Source, SourceDeltaKind, testutil};
    use testutil::{be16_at, be32_at, be64_at, qcow2_minimal, temp_dir, write};

    /// Assert that opening `bytes` fails with exactly `errno`.
    fn assert_open_errno(bytes: Vec<u8>, name: &str, errno: i32) {
        let OpenError(actual) = open_bytes(bytes, name).expect_err("open must fail");
        assert_eq!(actual, errno, "{name}");
    }

    fn open_bytes(bytes: Vec<u8>, name: &str) -> Result<Source, OpenError> {
        let dir = temp_dir(name);
        let path = write(&dir, "img.qcow", &bytes);
        Source::open(&format!(
            r#"{{"type":"qcow","stream":{{"type":"file","file_path":"{path}"}}}}"#
        ))
    }

    /// Spec vector 4: qcow2 minimal.
    #[test]
    fn qcow2_minimal_import() {
        let source = open_bytes(qcow2_minimal(), "qcow2-minimal").expect("prepare");
        assert!(source.snapshots().is_empty());
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(4096));
        assert_eq!(source.image_size(1), Err(-2));
        let head = source.read(CEPH_NOSNAP, &[(0, 4096)]).expect("HEAD read");
        assert_eq!(&head[..512], &[0x5a; 512]);
        assert!(head[512..].iter().all(|&b| b == 0));
        // A sub-cluster read and a read across a cluster boundary.
        assert_eq!(
            source.read(CEPH_NOSNAP, &[(100, 200)]).expect("slice"),
            vec![0x5a; 200]
        );
        let across = source.read(CEPH_NOSNAP, &[(400, 200)]).expect("across");
        assert_eq!(&across[..112], &[0x5a; 112]);
        assert!(across[112..].iter().all(|&b| b == 0));
        // Reads are not clamped to the size: cluster 8 is unallocated.
        assert_eq!(
            source.read(CEPH_NOSNAP, &[(4096, 512)]).expect("unclamped"),
            vec![0u8; 512]
        );
        // An L1 index beyond the table fails the whole read with -ERANGE.
        assert_eq!(source.read(CEPH_NOSNAP, &[(1 << 15, 512)]), Err(-34));
        // list_snaps over the full image: the data cluster is DATA, the
        // zero-flagged cluster is ZEROED against the empty baseline.
        let deltas = source
            .list_snaps(&[(0, 4096)], &[CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![RevisionDelta {
                snap_id: CEPH_NOSNAP,
                extents: vec![
                    extent(0, 512, SourceDeltaKind::Data),
                    extent(512, 512, SourceDeltaKind::Zeroed),
                ],
            }]
        );
    }

    fn extent(
        offset: u64,
        length: u64,
        kind: SourceDeltaKind,
    ) -> crate::migration_source::SourceDeltaExtent {
        crate::migration_source::SourceDeltaExtent {
            offset,
            length,
            kind,
        }
    }

    /// Spec vector 5: qcow2 with one snapshot.
    #[test]
    fn qcow2_snapshot_import() {
        let mut file = qcow2_minimal();
        file.resize(4096, 0);
        // Snapshot table: one entry at 2048.
        be32_at(&mut file, 60, 1);
        be64_at(&mut file, 64, 2048);
        // 40-byte snapshot header at 2048.
        be64_at(&mut file, 2048, 2560);
        be32_at(&mut file, 2056, 1);
        be16_at(&mut file, 2060, 1);
        be16_at(&mut file, 2062, 5);
        be32_at(&mut file, 2064, 1_700_000_000);
        be32_at(&mut file, 2068, 123_456_789);
        be32_at(&mut file, 2084, 16);
        // 16 bytes of extra data at 2088, disk_size at offset 8.
        be64_at(&mut file, 2096, 4096);
        // id "1" at 2104, name "snap1" at 2105.
        file[2104] = b'1';
        file[2105..2110].copy_from_slice(b"snap1");
        // Snapshot L1 at 2560 -> L2 at 3072, entry 0 = 3584.
        be64_at(&mut file, 2560, 3072);
        be64_at(&mut file, 3072, 3584);
        // Data cluster at 3584: 512 x 0x6b.
        file[3584..4096].fill(0x6b);

        let source = open_bytes(file, "qcow2-snapshot").expect("prepare");
        assert_eq!(
            source.snapshots(),
            vec![SourceSnapshot {
                id: 1,
                name: "snap1".into(),
                size: 4096,
                namespace: SnapshotNamespace::User,
                timestamp: SourceTimestamp {
                    sec: 1_700_000_000,
                    nsec: 123_456_789,
                },
            }]
        );
        assert_eq!(source.image_size(1), Ok(4096));
        let snap = source.read(1, &[(0, 4096)]).expect("snapshot read");
        assert_eq!(&snap[..512], &[0x6b; 512]);
        assert!(snap[512..].iter().all(|&b| b == 0));
        // HEAD is unchanged from vector 4.
        let head = source.read(CEPH_NOSNAP, &[(0, 1024)]).expect("HEAD read");
        assert_eq!(&head[..512], &[0x5a; 512]);
        // Per-revision sparse delta: the snapshot changed cluster 0, HEAD
        // changed it again and zero-flagged cluster 1.
        let deltas = source
            .list_snaps(&[(0, 4096)], &[1, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: vec![
                        extent(0, 512, SourceDeltaKind::Data),
                        extent(512, 512, SourceDeltaKind::Zeroed),
                    ],
                },
            ]
        );
    }

    /// Spec vector 6: qcow v1 minimal.
    #[test]
    fn qcow_v1_minimal_import() {
        let mut file = vec![0u8; 2048];
        be32_at(&mut file, 0, MAGIC);
        be32_at(&mut file, 4, 1);
        be64_at(&mut file, 24, 4096);
        file[32] = 9;
        file[33] = 6;
        be64_at(&mut file, 40, 512);
        be64_at(&mut file, 512, 1024);
        be64_at(&mut file, 1024, 1536);
        file[1536..2048].fill(0x76);

        let source = open_bytes(file, "qcow-v1").expect("prepare");
        assert!(source.snapshots().is_empty());
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(4096));
        let head = source.read(CEPH_NOSNAP, &[(0, 4096)]).expect("v1 read");
        assert_eq!(&head[..512], &[0x76; 512]);
        assert!(head[512..].iter().all(|&b| b == 0));
    }

    /// Spec vector 7: qcow2 refusals, one byte change on vector 4.
    #[test]
    fn qcow2_rejections() {
        let v3 = |change: fn(&mut Vec<u8>)| {
            let mut file = qcow2_minimal();
            be32_at(&mut file, 4, 3);
            change(&mut file);
            file
        };
        let cases: [(Vec<u8>, i32); 13] = [
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 0, 0x5146_49fc);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 4, 4);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 20, 8);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 20, 22);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be64_at(&mut file, 24, 4097);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 32, 1);
                    file
                },
                EINVAL,
            ),
            (
                {
                    let mut file = qcow2_minimal();
                    be32_at(&mut file, 36, 0);
                    file
                },
                EINVAL,
            ),
            (
                v3(|file| {
                    be32_at(file, 100, 112); // header_length > 104: read compression_type
                    file[104] = 1;
                }),
                EINVAL,
            ),
            (v3(|file| be64_at(file, 72, 1 << 3)), EINVAL),
            (v3(|file| be64_at(file, 72, 1 << 2)), ENOTSUP),
            (v3(|file| be64_at(file, 72, 1 << 4)), ENOTSUP),
            (v3(|file| be64_at(file, 72, 1 << 5)), EINVAL),
            (
                {
                    let mut file = qcow2_minimal();
                    be64_at(&mut file, 8, 2048);
                    be32_at(&mut file, 16, 8);
                    file
                },
                ENOTSUP,
            ),
        ];
        for (file, errno) in cases {
            assert_open_errno(file, "qcow2-rejects", errno);
        }
        // Incompatible bit 0 (dirty) is accepted and ignored.
        let mut dirty = qcow2_minimal();
        be32_at(&mut dirty, 4, 3);
        be64_at(&mut dirty, 72, 1);
        let source = open_bytes(dirty, "qcow2-dirty").expect("dirty is accepted");
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(4096));
        // A nonzero backing offset with size 0 is "no backing file".
        let mut no_backing = qcow2_minimal();
        be64_at(&mut no_backing, 8, 2048);
        assert!(open_bytes(no_backing, "qcow2-no-backing").is_ok());
    }

    /// Spec vector 8: a compressed L2 entry is read as -EINVAL.
    #[test]
    fn qcow2_compressed_entry_refused_at_read() {
        let mut file = qcow2_minimal();
        be64_at(&mut file, 1024, (1u64 << 62) | 1536);
        let source = open_bytes(file, "qcow2-compressed").expect("prepare succeeds");
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 512)]), Err(-22));
        // The zero-flagged cluster 1 is untouched.
        assert_eq!(
            source.read(CEPH_NOSNAP, &[(512, 512)]).expect("cluster 1"),
            vec![0u8; 512]
        );
    }

    /// v1 compressed entries (bit 63) are refused at read with -EINVAL.
    #[test]
    fn qcow_v1_compressed_entry_refused_at_read() {
        let mut file = vec![0u8; 2048];
        be32_at(&mut file, 0, MAGIC);
        be32_at(&mut file, 4, 1);
        be64_at(&mut file, 24, 4096);
        file[32] = 9;
        file[33] = 6;
        be64_at(&mut file, 40, 512);
        be64_at(&mut file, 512, 1024);
        be64_at(&mut file, 1024, (1u64 << 63) | 1536);
        file[1536..2048].fill(0x76);
        let source = open_bytes(file, "qcow-v1-compressed").expect("prepare succeeds");
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 512)]), Err(-22));
    }

    /// Spec vector 9 (qcow part): a 1024-byte file with a qcow2 header
    /// claiming data at 4096 prepares fine and fails the read with
    /// -ERANGE.
    #[test]
    fn qcow_truncated_container_fails_at_execute() {
        let mut file = qcow2_minimal();
        file.truncate(1024);
        let source = open_bytes(file, "qcow-truncated").expect("prepare succeeds");
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 512)]), Err(-34));
    }

    #[test]
    fn qcow_header_shorter_than_the_read_fails_at_prepare() {
        // 8 bytes: the magic read succeeds, the version header read fails.
        let mut file = qcow2_minimal();
        file.truncate(8);
        assert_open_errno(file, "qcow-8", ERANGE);
        // 4 bytes: even the magic read fails.
        let mut file = qcow2_minimal();
        file.truncate(4);
        assert_open_errno(file, "qcow-4", ERANGE);
        // v1: a 30-byte file has the magic but not the 48-byte header.
        let mut file = vec![0u8; 30];
        be32_at(&mut file, 0, MAGIC);
        be32_at(&mut file, 4, 1);
        assert_open_errno(file, "qcow-v1-30", ERANGE);
    }

    #[test]
    fn qcow_l1_table_past_eof_fails_at_prepare() {
        let mut file = qcow2_minimal();
        be64_at(&mut file, 40, 100_000);
        assert_open_errno(file, "qcow-l1-past-eof", ERANGE);
    }

    #[test]
    fn qcow_data_cluster_past_eof_fails_at_execute() {
        let mut file = qcow2_minimal();
        be64_at(&mut file, 1024, 1900); // the 512-byte cluster runs past 2048
        let source = open_bytes(file, "qcow-data-past-eof").expect("prepare");
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 512)]), Err(-34));
    }

    #[test]
    fn qcow_l1_overflow_guards() {
        // size just past u64::MAX - (1 << l1_shift) trips the first guard.
        let mut file = qcow2_minimal();
        be64_at(&mut file, 24, u64::MAX - (1 << 15) + 1);
        assert_open_errno(file, "qcow-overflow-a", EINVAL);
        // l1_count above INT32_MAX/8 trips the second guard.
        let mut file = qcow2_minimal();
        be64_at(&mut file, 24, 1u64 << 50);
        assert_open_errno(file, "qcow-overflow-b", EINVAL);
        // The v1 guards are the same.
        let mut v1 = vec![0u8; 2048];
        be32_at(&mut v1, 0, MAGIC);
        be32_at(&mut v1, 4, 1);
        be64_at(&mut v1, 24, 1u64 << 50);
        v1[32] = 9;
        v1[33] = 6;
        assert_open_errno(v1, "qcow-v1-overflow", EINVAL);
    }

    #[test]
    fn qcow_v1_header_bounds() {
        let v1 = |l2_bits: u8| {
            let mut file = vec![0u8; 2048];
            be32_at(&mut file, 0, MAGIC);
            be32_at(&mut file, 4, 1);
            be64_at(&mut file, 24, 4096);
            file[32] = 9;
            file[33] = l2_bits;
            be64_at(&mut file, 40, 512);
            file
        };
        assert_open_errno(v1(5), "qcow-v1-l2-low", EINVAL);
        assert_open_errno(v1(19), "qcow-v1-l2-high", EINVAL);
        // A v1 image reads with its own l2_bits geometry.
        let source = open_bytes(v1(6), "qcow-v1-l2-ok").expect("v1 l2_bits 6");
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(4096));
    }

    #[test]
    fn qcow_huge_l1_size_is_fine() {
        // Only the first l1_count entries are read; a larger l1_size is ok.
        let mut file = qcow2_minimal();
        be32_at(&mut file, 36, u32::MAX);
        let source = open_bytes(file, "qcow-huge-l1-size").expect("prepare");
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(4096));
    }

    #[test]
    fn qcow_snapshot_walk_past_eof_fails_at_prepare() {
        let mut file = qcow2_minimal();
        file.resize(2100, 0);
        be32_at(&mut file, 60, 1);
        be64_at(&mut file, 64, 2090); // the 40-byte header runs past the end
        assert_open_errno(file, "qcow-snap-past-eof", ERANGE);
    }

    #[test]
    fn qcow_snapshot_all_zero_sizes_keeps_size_zero() {
        let mut file = qcow2_minimal();
        file.resize(2100, 0);
        be32_at(&mut file, 60, 1);
        be64_at(&mut file, 64, 2048);
        // A 40-byte snapshot header with all sizes zero: no extra-data read,
        // no L1 read, size stays 0, name is a UUID.
        let source = open_bytes(file, "qcow-snap-zero").expect("prepare");
        let snap = source.snapshots().remove(0);
        assert_eq!(snap.id, 1);
        assert_eq!(snap.size, 0);
        assert_eq!(snap.name.len(), 36);
        assert_eq!(source.image_size(1), Ok(0));
        assert_eq!(source.read(1, &[(0, 512)]), Err(-34));
    }

    #[test]
    fn qcow_snapshot_extra_data_below_16_uses_head_size() {
        let mut file = qcow2_minimal();
        file.resize(2120, 0);
        be32_at(&mut file, 60, 1);
        be64_at(&mut file, 64, 2048);
        be64_at(&mut file, 2048, 2096); // snap L1
        be32_at(&mut file, 2056, 1);
        be16_at(&mut file, 2060, 0);
        be16_at(&mut file, 2062, 0);
        be32_at(&mut file, 2084, 8); // extra_data_size < 16
        be64_at(&mut file, 2096, 1024); // snap L1 -> L2
        be64_at(&mut file, 1024, 1536);
        let source = open_bytes(file, "qcow-snap-extra-small").expect("prepare");
        assert_eq!(source.snapshots()[0].size, 4096);
    }

    #[test]
    fn qcow_snapshots_offset_zero_means_no_snapshots() {
        let mut file = qcow2_minimal();
        be32_at(&mut file, 60, 3);
        be64_at(&mut file, 64, 0);
        let source = open_bytes(file, "qcow-snap-off-zero").expect("prepare");
        assert!(source.snapshots().is_empty());
    }

    #[test]
    fn qcow_unknown_snap_id() {
        let source = open_bytes(qcow2_minimal(), "qcow-unknown").expect("prepare");
        assert_eq!(source.image_size(7), Err(-2));
        assert_eq!(source.read(7, &[(0, 1)]), Err(-2));
        assert_eq!(source.list_snaps(&[(0, 1)], &[7]), Err(-2));
    }

    #[test]
    fn qcow_list_snaps_zeroed_classification() {
        // Two snapshots plus HEAD, all 4096 bytes: cluster 0 carries data in
        // every revision; the requested deltas classify the changes.
        let mut file = qcow2_minimal();
        file.resize(8192, 0);
        // HEAD: L1 at 512 -> L2 at 2048, entry 0 = 1536 (data C at 1536).
        be64_at(&mut file, 512, 2048);
        be64_at(&mut file, 2048, 1536);
        file[1536..2048].fill(0xc3);
        // Two snapshots at 3072 and 3136.
        be32_at(&mut file, 60, 2);
        be64_at(&mut file, 64, 3072);
        for (base, name) in [(3072, b"s1"), (3136, b"s2")] {
            be64_at(&mut file, base, 4096u64 + (base - 3072) as u64); // snap L1
            be32_at(&mut file, base + 8, 1);
            be16_at(&mut file, base + 12, 1); // id_str_size
            be16_at(&mut file, base + 14, name.len() as u16);
            be32_at(&mut file, base + 16, 1_700_000_000);
            be32_at(&mut file, base + 36, 16); // extra_data_size
            be64_at(&mut file, base + 40 + 8, 4096); // disk_size
            file[base + 56] = b'i'; // id string
            file[base + 57..base + 57 + name.len()].copy_from_slice(name);
        }
        // Snap1: L1 at 4096 -> L2 at 4608, entry 0 = 6144 (data A).
        be64_at(&mut file, 4096, 4608);
        be64_at(&mut file, 4608, 6144);
        file[6144..6656].fill(0xa1);
        // Snap2: L1 at 4160 -> L2 at 5120, entry 0 = 7168 (data B).
        be64_at(&mut file, 4160, 5120);
        be64_at(&mut file, 5120, 7168);
        file[7168..7680].fill(0xb2);

        let source = open_bytes(file, "qcow-list-zeroed").expect("prepare");
        assert_eq!(
            source
                .snapshots()
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["s1", "s2"]
        );
        // Every revision changed cluster 0.
        let deltas = source
            .list_snaps(&[(0, 1024)], &[1, 2, CEPH_NOSNAP])
            .expect("list_snaps");
        for delta in &deltas {
            assert_eq!(
                delta.extents,
                vec![extent(0, 512, SourceDeltaKind::Data)],
                "snap {}",
                delta.snap_id
            );
        }
        // Unrequested snap1 merges into snap2.
        let deltas = source.list_snaps(&[(0, 1024)], &[2]).expect("list_snaps");
        assert_eq!(
            deltas,
            vec![RevisionDelta {
                snap_id: 2,
                extents: vec![extent(0, 512, SourceDeltaKind::Data)],
            }]
        );
    }

    #[test]
    fn qcow_list_snaps_zeroed_kinds() {
        // Snap1 has data in cluster 0; snap2 drops it (now 0) and HEAD
        // zero-flags it (exactly 1).
        let mut file = qcow2_minimal();
        file.resize(6144, 0);
        // HEAD: L1 at 512 -> L2 at 1024 (from the base), entry 0 = 1.
        be64_at(&mut file, 1024, 1);
        be64_at(&mut file, 1032, 0);
        // Two snapshots at 2048 and 2112.
        be32_at(&mut file, 60, 2);
        be64_at(&mut file, 64, 2048);
        for (base, l1_off) in [(2048, 3072u64), (2112, 3584)] {
            be64_at(&mut file, base, l1_off);
            be32_at(&mut file, base + 8, 1);
            be16_at(&mut file, base + 12, 1); // id_str_size
            be16_at(&mut file, base + 14, 2); // name_size
            be32_at(&mut file, base + 36, 16); // extra_data_size
            be64_at(&mut file, base + 40 + 8, 4096); // disk_size
            file[base + 56] = b'i'; // id string
            file[base + 57..base + 59].copy_from_slice(b"s1"); // name
        }
        // Snap1: L1 at 3072 -> L2 at 4096, entry 0 = 5120 (data).
        be64_at(&mut file, 3072, 4096);
        be64_at(&mut file, 4096, 5120);
        file[5120..5632].fill(0xa1);
        // Snap2: L1 at 3584 -> L2 at 4608, entry 0 = 0 (dropped).
        be64_at(&mut file, 3584, 4608);

        let source = open_bytes(file, "qcow-zeroed-kinds").expect("prepare");
        let deltas = source
            .list_snaps(&[(0, 1024)], &[1, 2, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: 2,
                    extents: vec![extent(0, 512, SourceDeltaKind::Zeroed)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: vec![extent(0, 512, SourceDeltaKind::Zeroed)],
                },
            ]
        );
    }

    #[test]
    fn qcow_list_snaps_compares_against_previous_requested() {
        // s1 and HEAD carry the same data cluster; the unrequested s2
        // drops it. Comparing HEAD against the previous *requested*
        // revision (s1) yields no delta; accumulating s2's transition
        // would report DATA.
        let mut file = qcow2_minimal();
        file.resize(6144, 0);
        // HEAD: L1 at 512 -> L2 at 1024, entry 0 = 5120.
        be64_at(&mut file, 1024, 5120);
        be64_at(&mut file, 1032, 0);
        // Two snapshots at 2048 and 2112.
        be32_at(&mut file, 60, 2);
        be64_at(&mut file, 64, 2048);
        for (base, l1_off) in [(2048, 3072u64), (2112, 3584)] {
            be64_at(&mut file, base, l1_off);
            be32_at(&mut file, base + 8, 1);
            be16_at(&mut file, base + 12, 1); // id_str_size
            be16_at(&mut file, base + 14, 2); // name_size
            be32_at(&mut file, base + 36, 16); // extra_data_size
            be64_at(&mut file, base + 40 + 8, 4096); // disk_size
            file[base + 56] = b'i'; // id string
            file[base + 57..base + 59].copy_from_slice(b"s1"); // name
        }
        // s1: L1 at 3072 -> L2 at 4096, entry 0 = 5120 (data A).
        be64_at(&mut file, 3072, 4096);
        be64_at(&mut file, 4096, 5120);
        file[5120..5632].fill(0xa1);
        // s2: L1 at 3584 -> L2 at 4608, entry 0 = 0 (dropped).
        be64_at(&mut file, 3584, 4608);

        let source = open_bytes(file, "qcow-prev-requested").expect("prepare");
        // All requested: s1 DATA, s2 ZEROED, HEAD DATA (against s2).
        let deltas = source
            .list_snaps(&[(0, 1024)], &[1, 2, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: 2,
                    extents: vec![extent(0, 512, SourceDeltaKind::Zeroed)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
            ]
        );
        // s2 unrequested: HEAD compares against s1, whose entry is equal.
        let deltas = source
            .list_snaps(&[(0, 1024)], &[1, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn qcow_reads_are_consecutive_extents_in_order() {
        let source = open_bytes(qcow2_minimal(), "qcow-multi-extent").expect("prepare");
        let bytes = source
            .read(CEPH_NOSNAP, &[(300, 100), (0, 200), (4096, 512)])
            .expect("multi extent");
        assert_eq!(bytes.len(), 812);
        assert_eq!(&bytes[..100], &[0x5a; 100]);
        assert_eq!(&bytes[100..300], &[0x5a; 200]);
        assert!(bytes[300..].iter().all(|&b| b == 0));
    }

    #[test]
    fn qcow_read_huge_extent_total_is_enomem() {
        let source = open_bytes(qcow2_minimal(), "qcow-enomem-read").expect("prepare");
        // 2^60 bytes cannot be allocated: -ENOMEM, no panic.
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 1u64 << 60)]), Err(-12));
    }

    #[test]
    fn qcow_read_extent_at_u64_max() {
        let source = open_bytes(qcow2_minimal(), "qcow-read-max").expect("prepare");
        // Past the L1 table: the whole read fails -ERANGE, no overflow.
        assert_eq!(source.read(CEPH_NOSNAP, &[(u64::MAX - 512, 512)]), Err(-34));
    }

    #[test]
    fn qcow_list_snaps_extent_at_u64_max() {
        let source = open_bytes(qcow2_minimal(), "qcow-list-max").expect("prepare");
        // An extent ending at u64::MAX: everything past the L1-covered
        // range is unallocated; no overflow, no panic.
        let deltas = source
            .list_snaps(&[(0, u64::MAX)], &[CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![RevisionDelta {
                snap_id: CEPH_NOSNAP,
                extents: vec![
                    extent(0, 512, SourceDeltaKind::Data),
                    extent(512, 512, SourceDeltaKind::Zeroed),
                ],
            }]
        );
    }

    #[test]
    fn qcow_huge_header_counts_do_not_panic() {
        // Maximal nb_snapshots from the header: the snapshots vector
        // reservation and the header walk must fail with a clean errno
        // (-ENOMEM when the reservation fails, -ERANGE when the small file
        // ends first), never panic.
        let mut file = qcow2_minimal();
        file.resize(2120, 0);
        be32_at(&mut file, 60, u32::MAX);
        be64_at(&mut file, 64, 2048);
        assert!(matches!(
            open_bytes(file, "qcow-huge-nb-snaps"),
            Err(OpenError(-12)) | Err(OpenError(-34))
        ));
    }
}
