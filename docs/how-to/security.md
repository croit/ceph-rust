# How to secure the OSD

croit-flashstore-osd authenticates with cephx like a classic OSD. This page covers the keyring, the admin socket, the `ceph tell` permission check and the network layout.

## Authentication

Cluster and service traffic require cephx. Client connections accept cephx or no authentication, so that a client can reach the OSD in the same way it reaches classic OSDs.

The OSD uses msgr2 only. msgr1 is not bound.

## Keyring

The OSD key is created when the store is made with `croit-flashstore-tool mkfs`:

```
croit-flashstore-tool mkfs --dev <spec> --mon-host <addr> --keyring <file> --entity <name>
```

- `--keyring` defaults to `/etc/ceph/ceph.client.bootstrap-osd.keyring`. Pass the keyring explicitly if your bootstrap keyring is elsewhere.
- `--entity` selects the key inside the keyring. `mkfs` fails if the keyring has no key for it.

`mkfs` stores the key in the device record only. `croit-flashstore-tool prepare` also writes it to the file `keyring` in the OSD data directory, which the daemon reads at start; make that file readable only by the daemon user. `prepare` defaults `--keyring` to `/var/lib/ceph/bootstrap-osd/<cluster>.keyring`, `mkfs` to the path above.

To replace the key without recreating the OSD or restarting it:

1. Make the new key pending on the mon (`ceph auth rotate osd.<id>`, or let the orchestrator do it) and write it to a file.
2. `ceph tell osd.<id> rotate-stored-key -i <keyfile>` stores it for the next start (device record and `keyring` in the OSD data directory).
3. `ceph tell osd.<id> rotate-key -i <keyfile>` switches the running daemon to it. Its next authentication uses the new key.

If step 3 fails, restart the OSD. `ceph tell osd.<id> wipe-rotating-secrets` drops the daemon's rotating secrets and tickets and fetches new ones at once.

The daemon reads `auth_service_ticket_ttl` at run time. If its rotating keys expired more than that long ago, it logs a `possible clock skew` warning: check the time sync of the host.

## Admin socket

The admin socket is `/var/run/ceph/<cluster>-osd.<id>.asok`, or the path set by `admin_socket`. The daemon sets its mode to `0660`. If that call fails, the daemon continues and does not log an error, so check the mode after start:

```
stat -c '%a %U:%G' /var/run/ceph/ceph-osd.0.asok
```

The daemon does not check the identity of the caller on the socket. Access is controlled only by the file mode and the owner. Anyone who can open the socket can run admin commands on the OSD. Grant access only to the account that runs `croit-flashstore-tool asok`, for example by group.

## `ceph tell` permissions

A `ceph tell` command is accepted only if the caller's capabilities contain `allow *` or `allow all`. Other callers receive `EACCES` (access denied) and the attempt is logged as `tell from <entity> denied (caps)`.

The check does not separate read and write commands: any entity with `allow *` can run every command, including `repair` and `mark_unfound_lost`. Give that capability only to operators.

## Connection encryption

Encryption (msgr2 secure mode) is negotiated per connection. The mode options are `ms_cluster_mode`, `ms_service_mode`, `ms_mon_cluster_mode` and `ms_mon_client_mode`. Invalid values are ignored and the default is kept.

Encryption costs CPU and throughput. This page does not give measured figures.

## Kernel RBD clients without aes256k support

A Ceph v21 cluster creates cephx keys of type `aes256k` and allows only that type. Kernel clients (krbd, kernel CephFS) whose libceph lacks `aes256k` cannot load such a key: `rbd map` fails with `(22) Invalid argument` and the client kernel log shows `libceph: secret too big 32`. This affects every v21 cluster, with croit-flashstore-osd or classic OSDs. Check the cluster setting with `ceph --format=json mon dump | jq -r '.auth_allowed_ciphers | map(.name) | join(",")'`.

To serve such a client, give it its own AES-128 key:

```
ceph mon set auth_allowed_ciphers aes,aes256k
ceph config set mon mon_auth_allow_insecure_key true
ceph auth get-or-create client.krbd mon 'profile rbd' osd 'profile rbd pool=<pool>' --key_type aes > /etc/ceph/ceph.client.krbd.keyring
ceph config rm mon mon_auth_allow_insecure_key
```

Copy the keyring to the client, then map with `rbd --id krbd map <pool>/<image>`.

Security trade-off:

- `auth_allowed_ciphers aes,aes256k` lets every entity authenticate with the older AES-128 type. Ceph treats AES-128 keys as insecure. Keep the list at `aes256k` when no old kernel client remains: `ceph mon set auth_allowed_ciphers aes256k`. Rotate every AES-128 key or remove it first.
- `mon_auth_allow_insecure_key true` lets anyone with `auth` capabilities create AES-128 keys. Remove it right after creating the client keys, as above. While it is set, the cluster raises the `AUTH_INSECURE_KEYS_CREATABLE` health warning.
- Give the AES-128 client only the capabilities it needs, here one pool.

The better fix is a client kernel with `aes256k` support. Then the client can use a default key.

## Network layout

Set the networks in the cluster configuration:

- `public_network`: client and monitor traffic,
- `cluster_network`: replication and heartbeat traffic between OSDs.

Both are empty by default. With `public_network` empty, the OSD takes the address inside `cluster_network` if set, otherwise the `--ip` value, otherwise the address the kernel routes towards the peer. Restrict both networks at the switch or host firewall, not only in the configuration.

## Related

- [Reference: configuration](../reference/configuration.md)
- [Reference: admin commands](../reference/admin-commands.md)
- [How to monitor the OSD](monitor.md)
