# Reference: glossary

Terms as used in this manual.

**Acting set**
: The OSDs that currently serve a PG, in order. The first is the primary. Compare *up set*.

**Admin socket**
: Unix socket of a running daemon, `/var/run/ceph/<cluster>-osd.<id>.asok` by default. `croit-flashstore-tool asok` sends admin commands through it. See [admin commands](admin-commands.md).

**Backfill**
: Copying a PG's objects to an OSD that lacks them, while the PG stays available.

**Classic OSD**
: An OSD built from Ceph's own `ceph-osd` daemon, usually on BlueStore. croit-flashstore-osd and classic OSDs can share a cluster.

**Chunk**
: A fixed-size unit of store space. A shard owns a base share of chunks and can borrow more from a shared pool. See `flashstore_store_lend_*` in [configuration](configuration.md).

**Checkpoint**
: A point at which the store writes its state to the device. Blocks freed before a checkpoint become reusable only after it passes. `repair` writes one.

**cephx**
: Ceph's authentication protocol. Keys live in the keyring. See [how to secure the OSD](../how-to/security.md).

**Credit (RDMA)**
: Permission to send one RDMA message, granted by the receiver for one posted receive slot. A sender without credit waits. See [the RDMA transport](../explanation/rdma.md).

**CRUSH device class**
: A label on an OSD, for example `nvme`. CRUSH rules select OSDs by class. The class is set at prepare time with `--crush-device-class`.

**Epoch**
: Version number of an OSD map. Each change to the cluster map creates a new epoch.

**Erasure-coded (EC) pool**
: A pool that stores data as coded shards. croit-flashstore-osd does not store the shards of unsupported EC pools. See [how to handle erasure-coded pools](../how-to/erasure-pools.md).

**Fsck**
: Check of the store. It writes no checkpoint, but its mount can rewrite a superblock copy that differs from the other copy. See [how to maintain the store](../how-to/store-maintenance.md).

**Hugepages**
: Large memory pages reserved on the host for SPDK (DPDK environment). croit-flashstore-osd needs `flashstore_hugepages_mb` per OSD. See [how to prepare the host](../how-to/prepare-host.md).

**IOMMU group**
: Set of devices the IOMMU isolates together. Needed for `vfio-pci`, which the SPDK tier uses.

**Kernel TCP (`kernel`)**
: The default tier for this manual. It uses the kernel network stack through io_uring and needs no NIC binding.

**Map**
: Short for OSD map. See *epoch*.

**Peering**
: The process in which the OSDs of a PG agree on its state before serving I/O.

**PG (placement group)**
: A group of objects that share a set of OSDs. Each PG is served by one primary.

**PLP (power-loss protection)**
: NVMe device feature that completes acknowledged writes after power loss. croit-flashstore-osd requires it. A volatile write cache without PLP makes `mkfs` refuse the device. See [hardware requirements](hardware-requirements.md).

**Pool**
: A named set of PGs with one replication or erasure-coding policy.

**Primary**
: The first OSD of a PG's acting set. It serves client I/O for the PG.

**QP (queue pair)**
: The send and receive queues of one RDMA connection. croit-flashstore-osd uses one reliable-connected (RC) QP per upgraded msgr2 connection. See [the RDMA transport](../explanation/rdma.md).

**Recovery**
: Repair of a PG after an OSD failure, by copying the objects that a copy lacks from the others.

**Replicated pool**
: A pool that stores full copies of each object. This is the pool type croit-flashstore-osd stores.

**RoCEv2**
: RDMA over Converged Ethernet, version 2: RDMA carried in UDP/IP packets, routable, addressed by the IP of a network interface. The only RDMA flavor croit-flashstore-osd supports.

**Scrub**
: Comparison of the replicas of a PG. A deep scrub also compares the data. See [admin commands](admin-commands.md).

**Shard (store shard)**
: One part of the store. Each shard has its own write-ahead log ring and its own NVMe queue pair. The count is `flashstore_store_shards`, fixed at prepare time.

**SRQ (shared receive queue)**
: One pool of receive slots shared by all RDMA sessions of a core. Its size is set by `flashstore_rdma_memory`. See [the RDMA transport](../explanation/rdma.md).

**Superblock**
: Store header on the device, in two copies (A and B). It records the layout and the store features.

**Tier**
: The transport: kernel TCP over io_uring.

**Unfound object**
: An object whose latest version no available OSD has. See [how to recover a PG](../how-to/recover-pg.md).

**Up set**
: The OSDs that CRUSH currently maps to a PG. It can differ from the acting set during a change.

**WAL (write-ahead log)**
: Ring of records in the store. A transaction is acknowledged once its record is durable. After a crash the store replays the WAL.
