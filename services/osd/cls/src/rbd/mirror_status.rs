// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mirror image status / instance methods on `rbd_mirroring` (cls_rbd.md C.3.4). Liveness of a
//! status = its recorded origin is among the object's current watchers.

use super::mirror_types::*;
use super::types::MirrorImage;
use super::*;
use crate::ctx::{ClsCtx, omap_scan};
use crate::errno::*;
use denc::types::EntityInst;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow::{Break, Continue};

const IMAGE_PFX: &str = "image_";
const LOCAL_PFX: &str = "status_global_";
const REMOTE_PFX: &str = "remote_status_global_";

fn remote_prefix(gid: &[u8]) -> Vec<u8> {
    [REMOTE_PFX.as_bytes(), gid, b"_"].concat()
}
fn site_key(gid: &[u8], uuid: &[u8]) -> Vec<u8> {
    if uuid.is_empty() {
        key(LOCAL_PFX, gid)
    } else {
        [remote_prefix(gid).as_slice(), uuid].concat()
    }
}

/// Sanitized endpoints currently watching the object; ENOENT = none.
fn watchers<C: ClsCtx>(c: &mut C) -> Result<Vec<EntityInst>, Errno> {
    match c.list_watchers() {
        Ok(w) => Ok(w
            .into_iter()
            .map(|w| {
                sanitize(EntityInst {
                    name: w.name,
                    addr: w.addr,
                })
            })
            .collect()),
        Err(ENOENT) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Drop every site status (local + all remotes) of one global image id.
pub(super) fn status_remove_all<C: ClsCtx>(c: &mut C, gid: &[u8]) -> Result<(), Errno> {
    let pfx = remote_prefix(gid);
    for (k, _) in scan(c, &pfx, &pfx, u64::MAX)? {
        c.omap_remove_key(&k)?;
    }
    rm_ok(c, &site_key(gid, b""))
}

fn site_from(key_uuid: &[u8], raw: &[u8], live: &[EntityInst]) -> Result<SiteStatus, Errno> {
    let od: OnDiskStatus = dec_stored(raw)?;
    let mut s = od.status;
    s.up = live.contains(&od.origin);
    s.mirror_uuid = key_uuid.to_vec();
    Ok(s)
}

/// Local status first, then remotes by key order; ENOENT when there is none.
fn image_status<C: ClsCtx>(
    c: &mut C,
    gid: &[u8],
    live: &[EntityInst],
) -> Result<ImageStatus, Errno> {
    let mut st = ImageStatus::default();
    if let Some(raw) = rd_opt_raw(c, &site_key(gid, b""))? {
        st.sites.push(site_from(b"", &raw, live)?);
    }
    let pfx = remote_prefix(gid);
    for (k, v) in scan(c, &pfx, &pfx, u64::MAX)? {
        let uuid = suffix(&k, pfx.len());
        st.sites.push(site_from(&uuid, &v, live)?);
    }
    if st.sites.is_empty() {
        return Err(ENOENT);
    }
    Ok(st)
}

pub fn mirror_image_status_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let gid = Vec::<u8>::decode(&mut d).inval()?;
    let site = SiteStatus::decode(&mut d).inval()?;
    // unknown / disabled images are silently ignored
    let Ok(raw) = rd(c, &key("global_", &gid)) else {
        return Ok(Vec::new());
    };
    let Ok(image_id) = Vec::<u8>::decode(&mut input(&raw)) else {
        return Ok(Vec::new());
    };
    let Ok(raw) = rd(c, &key("image_", &image_id)) else {
        return Ok(Vec::new());
    };
    let Ok(img) = MirrorImage::decode(&mut input(&raw)) else {
        return Ok(Vec::new());
    };
    if img.state != IMG_ENABLED && img.state != IMG_CREATING {
        return Ok(Vec::new());
    }
    let o = c.origin();
    let skey = site_key(&gid, &site.mirror_uuid);
    let od = OnDiskStatus {
        origin: EntityInst {
            name: o.name,
            addr: o.addr,
        },
        status: SiteStatus {
            mirror_uuid: Vec::new(),
            up: false,
            last_update: c.now(),
            ..site
        },
    };
    wr(c, &skey, &enc_f(&od, c.osd_features())?)?;
    Ok(Vec::new())
}

pub fn mirror_image_status_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let gid = Vec::<u8>::decode(&mut input(inp)).inval()?;
    status_remove_all(c, &gid)?;
    Ok(())
}

pub fn mirror_image_status_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let gid = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let live = watchers(c)?;
    enc(&image_status(c, &gid, &live)?)
}

pub fn mirror_image_status_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let live = watchers(c)?;
    let from = key(IMAGE_PFX, &start);
    let mut images: BTreeMap<Vec<u8>, MirrorImage> = BTreeMap::new();
    let mut statuses: BTreeMap<Vec<u8>, ImageStatus> = BTreeMap::new();
    for (k, v) in scan(c, IMAGE_PFX, &from, max)? {
        let id = suffix(&k, IMAGE_PFX.len());
        let img: MirrorImage = dec_stored(&v)?;
        if let Ok(st) = image_status(c, &img.global_image_id, &live) {
            statuses.insert(id.clone(), st);
        }
        images.insert(id, img);
    }
    let mut o = enc(&images)?;
    o.extend(enc(&statuses)?);
    Ok(o)
}

/// Aggregate state of one image for the summary (peer direction decides which sites count).
fn summary_state(dir: u8, tx_uuids: &BTreeSet<Vec<u8>>, st: &ImageStatus) -> u8 {
    let mut state: Option<u8> = None;
    let mut unmatched = 0usize;
    if (dir == DIR_RX || dir == DIR_RX_TX)
        && let Some(l) = st.local().filter(|l| l.up)
    {
        state = Some(l.state);
    }
    if dir == DIR_TX || dir == DIR_RX_TX {
        unmatched = tx_uuids.len();
        for r in st.sites.iter().filter(|s| !s.mirror_uuid.is_empty()) {
            if unmatched > 0 && tx_uuids.contains(&r.mirror_uuid) {
                unmatched -= 1;
            }
            let rs = if r.up { r.state } else { ST_UNKNOWN };
            state = match state {
                _ if r.state == ST_ERROR => Some(r.state),
                None => Some(rs),
                Some(cur) if cur != ST_ERROR => Some(cur.min(rs)),
                keep => keep,
            };
        }
    }
    match state {
        Some(s) if unmatched == 0 => s,
        _ => ST_UNKNOWN,
    }
}

pub fn mirror_image_status_get_summary<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let peers: Vec<MirrorPeer> = if d.is_empty() {
        Vec::new()
    } else {
        Vec::decode(&mut d).inval()?
    };
    let mut dir = peers.first().map_or(DIR_RX, |p| p.direction);
    let mut tx = BTreeSet::new();
    for p in peers.iter().filter(|p| p.direction != DIR_RX) {
        tx.insert(p.mirror_uuid.clone());
        if dir != DIR_RX_TX && dir != p.direction {
            dir = DIR_RX_TX;
        }
    }
    let live = watchers(c)?;
    let mut states: BTreeMap<u8, i32> = BTreeMap::new();
    for (_, v) in scan(c, IMAGE_PFX, IMAGE_PFX.as_bytes(), u64::MAX)? {
        let img: MirrorImage = dec_stored(&v)?;
        let st = match image_status(c, &img.global_image_id, &live) {
            Ok(s) => s,
            Err(ENOENT) => ImageStatus::default(),
            Err(e) => return Err(e),
        };
        let n = states.entry(summary_state(dir, &tx, &st)).or_insert(0);
        *n = n.wrapping_add(1);
    }
    enc(&states)
}

pub fn mirror_image_status_remove_down<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    let live = watchers(c)?;
    for pfx in [LOCAL_PFX, REMOTE_PFX] {
        for (k, v) in scan(c, pfx, pfx.as_bytes(), u64::MAX)? {
            let origin = OnDiskStatus::decode_origin(&mut input(&v)).eio()?;
            if !live.contains(&origin) {
                c.omap_remove_key(&k)?;
            }
        }
    }
    Ok(())
}

/// Origin of the local-site status when it is still watching, else ESTALE; ENOENT w/o status.
fn instance_of<C: ClsCtx>(c: &mut C, gid: &[u8], live: &[EntityInst]) -> Result<EntityInst, Errno> {
    let raw = rd(c, &site_key(gid, b""))?;
    let od: OnDiskStatus = dec_stored(&raw)?;
    if live.contains(&od.origin) {
        Ok(od.origin)
    } else {
        Err(ESTALE)
    }
}

pub fn mirror_image_instance_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let gid = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let live = watchers(c)?;
    let i = instance_of(c, &gid, &live)?;
    enc_f(&i, c.osd_features())
}

pub fn mirror_image_instance_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let live = watchers(c)?;
    let mut out: BTreeMap<Vec<u8>, EntityInst> = BTreeMap::new();
    // images without a live instance are skipped and do not count towards `max`
    if max > 0 {
        let start = key(IMAGE_PFX, &start);
        omap_scan(c, &start, IMAGE_PFX.as_bytes(), u64::MAX, |c, k, v| {
            let img: MirrorImage = dec_stored(&v)?;
            if let Ok(i) = instance_of(c, &img.global_image_id, &live) {
                out.insert(suffix(&k, IMAGE_PFX.len()), i);
            }
            Ok(if out.len() as u64 >= max {
                Break(())
            } else {
                Continue(())
            })
        })?;
    }
    enc_f(&out, c.osd_features())
}
