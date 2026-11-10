// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mirroring methods on the pool object `rbd_mirroring` (cls_rbd.md C.3). Status/instance methods
//! live in `mirror_status.rs`.

use super::mirror_status::status_remove_all;
use super::mirror_types::*;
use super::types::*;
use super::*;
use crate::ctx::{ClsCtx, rand_uuid_text};
use crate::errno::*;
use std::collections::BTreeMap;

const UUID_KEY: &str = "mirror_uuid";
const MODE_KEY: &str = "mirror_mode";
const NS_KEY: &str = "remote_namespace";
const PEER_PFX: &str = "mirror_peer_";
const IMAGE_PFX: &str = "image_";

/// Stored u32 mode (`ENOENT` = never set). Undecodable value -> EIO.
fn mode<C: ClsCtx>(c: &mut C) -> Result<Option<u32>, Errno> {
    match rd_opt_raw(c, MODE_KEY)? {
        Some(v) => Ok(Some(Decoder::new(&v).u32().eio()?)),
        None => Ok(None),
    }
}

/// Pool mirroring must be configured and not DISABLED, else EINVAL.
fn require_enabled<C: ClsCtx>(c: &mut C) -> Result<(), Errno> {
    match mode(c)? {
        None | Some(MODE_DISABLED) => Err(EINVAL),
        Some(_) => Ok(()),
    }
}

/// Stored pool uuid is the raw string bytes (no length prefix).
fn pool_uuid<C: ClsCtx>(c: &mut C) -> Result<Vec<u8>, Errno> {
    rd(c, UUID_KEY)
}

fn peer_key(uuid: &[u8]) -> Vec<u8> {
    key(PEER_PFX, uuid)
}

fn read_peers<C: ClsCtx>(c: &mut C) -> Result<Vec<MirrorPeer>, Errno> {
    scan(c, PEER_PFX, PEER_PFX.as_bytes(), u64::MAX)?
        .iter()
        .map(|(_, v)| dec_stored(v))
        .collect()
}
fn read_peer<C: ClsCtx>(c: &mut C, uuid: &[u8]) -> Result<MirrorPeer, Errno> {
    dec_stored(&rd(c, &peer_key(uuid))?)
}
fn write_peer<C: ClsCtx>(c: &mut C, p: &MirrorPeer) -> Result<(), Errno> {
    wr(c, &peer_key(&p.uuid), &enc(p)?)
}

fn image_get<C: ClsCtx>(c: &mut C, id: &[u8]) -> Result<MirrorImage, Errno> {
    dec_stored(&rd(c, &key(IMAGE_PFX, id))?)
}

// ---- pool uuid / mode / remote namespace --------------------------------------------------------

pub fn mirror_uuid_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    enc(&pool_uuid(c)?)
}

pub fn mirror_uuid_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let u = Vec::<u8>::decode(&mut input(inp)).inval()?;
    if u.is_empty() {
        return Err(EINVAL);
    }
    if matches!(mode(c)?, Some(m) if m != MODE_DISABLED) {
        return Err(EINVAL);
    }
    wr(c, UUID_KEY, &u)?;
    Ok(())
}

pub fn mirror_mode_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let v = rd(c, MODE_KEY)?;
    let m = Decoder::new(&v).u32().eio()?;
    Ok(m.to_le_bytes().to_vec())
}

pub fn mirror_mode_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let m = input(inp).u32().inval()?;
    match m {
        MODE_DISABLED => {
            if !read_peers(c)?.is_empty() {
                return Err(EBUSY);
            }
            rm_ok(c, MODE_KEY)?;
            rm_ok(c, UUID_KEY)?;
            rm_ok(c, NS_KEY)?;
        }
        MODE_IMAGE | MODE_POOL | MODE_INIT_ONLY => {
            match pool_uuid(c) {
                Err(ENOENT) => return Err(EINVAL),
                Err(e) => return Err(e),
                Ok(_) => {}
            }
            wr(c, MODE_KEY, &m.to_le_bytes())?;
        }
        _ => return Err(EINVAL),
    }
    Ok(Vec::new())
}

pub fn mirror_remote_namespace_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let s: Vec<u8> = dec_stored(&rd(c, NS_KEY)?)?;
    enc(&s)
}

pub fn mirror_remote_namespace_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let ns = Vec::<u8>::decode(&mut input(inp)).inval()?;
    if matches!(mode(c)?, Some(m) if m != MODE_DISABLED && m != MODE_INIT_ONLY) {
        return Err(EINVAL);
    }
    wr(c, NS_KEY, &enc(&ns)?)?;
    Ok(())
}

// ---- peers ---------------------------------------------------------------------------------------

/// Peer liveness ping from a remote site (always TX direction on the wire).
pub fn mirror_peer_ping<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let site = Vec::<u8>::decode(&mut d).inval()?;
    let muuid = Vec::<u8>::decode(&mut d).inval()?;
    let dir = d.u8().inval()?;
    if dir != DIR_TX {
        return Err(EINVAL);
    }
    require_enabled(c)?;
    if site.is_empty() || muuid.is_empty() {
        return Err(EINVAL);
    }
    let mut peers = read_peers(c)?;
    let by_site = peers.iter().position(|p| p.site_name == site);
    let mut by_uuid = None;
    if by_site.is_none_or(|i| !peers[i].mirror_uuid.is_empty() && peers[i].mirror_uuid != muuid) {
        by_uuid = peers.iter().position(|p| p.mirror_uuid == muuid);
    }
    let idx = if let Some(u) = by_uuid {
        // matched by mirror uuid; a remote that renamed its site is followed, two peers keep names
        if by_site.is_none() {
            peers[u].site_name = site.clone();
        }
        Some(u)
    } else if let Some(s) = by_site {
        // peer registered without mirror uuid: learn it
        peers[s].mirror_uuid = muuid.clone();
        Some(s)
    } else {
        None
    };
    let mut peer = match idx {
        Some(i) => {
            let mut p = peers.swap_remove(i);
            if p.direction == DIR_RX {
                p.direction = DIR_RX_TX;
            }
            p
        }
        None => {
            // auto-register a TX-only peer under a fresh uuid
            let mut uuid = rand_uuid_text(c);
            for _ in 0..8 {
                if rd_opt_raw(c, &peer_key(&uuid))?.is_none() {
                    break;
                }
                uuid = rand_uuid_text(c);
            }
            MirrorPeer {
                uuid,
                direction: DIR_TX,
                site_name: site,
                mirror_uuid: muuid,
                ..Default::default()
            }
        }
    };
    peer.last_seen = c.now();
    if !peer.is_valid() {
        return Err(EINVAL);
    }
    write_peer(c, &peer)?;
    Ok(())
}

/// Peers are re-encoded in the current layout.
pub fn mirror_peer_list<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    enc(&read_peers(c)?)
}

pub fn mirror_peer_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let p = MirrorPeer::decode(&mut input(inp)).inval()?;
    require_enabled(c)?;
    if !p.is_valid() {
        return Err(EINVAL);
    }
    let pool = pool_uuid(c)?;
    if pool == p.uuid.as_slice() || p.direction == DIR_TX {
        return Err(EINVAL);
    }
    for q in read_peers(c)? {
        if q.uuid == p.uuid {
            return Err(ESTALE);
        }
        if q.site_name == p.site_name {
            return Err(EEXIST);
        }
        if !p.mirror_uuid.is_empty() && q.mirror_uuid == p.mirror_uuid {
            return Err(EEXIST);
        }
    }
    write_peer(c, &p)?;
    Ok(())
}

pub fn mirror_peer_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let uuid = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rm_ok(c, &peer_key(&uuid))?;
    Ok(())
}

pub fn mirror_peer_set_client<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let uuid = Vec::<u8>::decode(&mut d).inval()?;
    let client = Vec::<u8>::decode(&mut d).inval()?;
    let mut p = read_peer(c, &uuid)?;
    p.client_name = client;
    write_peer(c, &p)?;
    Ok(())
}

pub fn mirror_peer_set_cluster<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let uuid = Vec::<u8>::decode(&mut d).inval()?;
    let site = Vec::<u8>::decode(&mut d).inval()?;
    let mut target = None;
    for p in read_peers(c)? {
        if p.uuid == uuid {
            target = Some(p);
        } else if p.site_name == site {
            return Err(EEXIST);
        }
    }
    let mut p = target.ok_or(ENOENT)?;
    p.site_name = site;
    write_peer(c, &p)?;
    Ok(())
}

pub fn mirror_peer_set_direction<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let uuid = Vec::<u8>::decode(&mut d).inval()?;
    let dir = d.u8().inval()?;
    let mut p = read_peer(c, &uuid)?;
    p.direction = dir;
    write_peer(c, &p)?;
    Ok(())
}

// ---- mirrored images -----------------------------------------------------------------------------

pub fn mirror_image_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    enc(&image_get(c, &id)?)
}

pub fn mirror_image_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let id = Vec::<u8>::decode(&mut d).inval()?;
    let m = MirrorImage::decode(&mut d).inval()?;
    let gkey = key("global_", &m.global_image_id);
    match image_get(c, &id) {
        Err(ENOENT) => {
            if rd_opt_raw(c, &gkey)?.is_some() {
                return Err(EEXIST);
            }
            // creating straight into DISABLING = lost a race with disable (upstream answers ENOENT)
            if m.state == IMG_DISABLING {
                return Err(ENOENT);
            }
        }
        Err(e) => return Err(e),
        Ok(old) if old.global_image_id != m.global_image_id => return Err(EINVAL),
        Ok(_) => {}
    }
    wr(c, &key(IMAGE_PFX, &id), &enc(&m)?)?;
    wr(c, &gkey, &enc(&id)?)?;
    Ok(Vec::new())
}

pub fn mirror_image_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let m = image_get(c, &id)?;
    if m.state != IMG_DISABLING {
        return Err(EBUSY);
    }
    rm(c, &key(IMAGE_PFX, &id))?;
    rm(c, &key("global_", &m.global_image_id))?;
    status_remove_all(c, &m.global_image_id)?;
    Ok(())
}

pub fn mirror_image_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key(IMAGE_PFX, &start);
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (k, v) in scan(c, IMAGE_PFX, &from, max)? {
        let m: MirrorImage = dec_stored(&v)?;
        out.insert(suffix(&k, IMAGE_PFX.len()), m.global_image_id);
    }
    enc(&out)
}

pub fn mirror_image_get_image_id<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let g = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let id: Vec<u8> = dec_stored(&rd(c, &key("global_", &g))?)?;
    enc(&id)
}

// ---- rbd-mirror daemon instances / image map -----------------------------------------------------

pub fn mirror_instances_list<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    const P: &str = "instance_";
    let ids: Vec<Vec<u8>> = scan(c, P, P.as_bytes(), u64::MAX)?
        .into_iter()
        .map(|(k, _)| suffix(&k, P.len()))
        .collect();
    enc(&ids)
}

pub fn mirror_instances_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    wr(c, &key("instance_", &id), &[])?;
    Ok(())
}

pub fn mirror_instances_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rm(c, &key("instance_", &id))?;
    Ok(())
}

pub fn mirror_image_map_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    const P: &str = "image_map_";
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key(P, &start);
    let mut out: BTreeMap<Vec<u8>, ImageMap> = BTreeMap::new();
    for (k, v) in scan(c, P, &from, max)? {
        // undecodable payload answers EINVAL here (upstream quirk)
        out.insert(suffix(&k, P.len()), dec_op(&v)?);
    }
    enc(&out)
}

pub fn mirror_image_map_update<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let gid = Vec::<u8>::decode(&mut d).inval()?;
    let m = ImageMap::decode(&mut d).inval()?;
    wr(c, &key("image_map_", &gid), &enc(&m)?)?;
    Ok(())
}

pub fn mirror_image_map_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let gid = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rm_ok(c, &key("image_map_", &gid))?;
    Ok(())
}

// ---- snapshot-based mirroring: per-snapshot bookkeeping ------------------------------------------

pub fn mirror_image_snapshot_unlink_peer<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let snap_id = d.u64().inval()?;
    let peer = Vec::<u8>::decode(&mut d).inval()?;
    let mut s = read_snap(c, snap_id)?;
    let SnapNs::Mirror { peer_uuids, .. } = &mut s.ns else {
        return Err(EINVAL);
    };
    if !peer_uuids.remove(&peer) {
        return Err(ENOENT);
    }
    write_snap(c, s)?;
    Ok(())
}

pub fn mirror_image_snapshot_set_copy_progress<C: ClsCtx>(
    c: &mut C,
    inp: &[u8],
) -> Result<(), Errno> {
    let mut d = input(inp);
    let snap_id = d.u64().inval()?;
    let done = d.bool().inval()?;
    let last = d.u64().inval()?;
    let mut s = read_snap(c, snap_id)?;
    let SnapNs::Mirror {
        state,
        complete,
        last_copied_object_number,
        ..
    } = &mut s.ns
    else {
        return Err(EINVAL);
    };
    *complete = done;
    // only non-primary snapshots track the copy position
    if *state == 2 || *state == 3 {
        *last_copied_object_number = last;
    }
    write_snap(c, s)?;
    Ok(())
}
