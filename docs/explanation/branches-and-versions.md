# Explanation: branches and versions

croit-flashstore-osd is built for one Ceph release at a time. Each supported release lives on its own branch of the project repository. Use the branch that matches your cluster's Ceph release. A build or a documentation page from another branch can target a different Ceph release and will not be wire-compatible with your cluster.

## Branches

| Branch | Ceph release | Ceph codename | Use it for |
|---|---|---|---|
| `main` | v21.2.0 | umbrella | Clusters running Ceph v21.2.0 |
| `v20.2.4` | v20.2.4 | tentacle | Clusters running Ceph v20.2.4 |

New release branches are added as the supported Ceph releases change. The table above lists the branches that exist at the time of writing. Check the branch list in the project repository for the current set.

## How to choose

1. Find your cluster's Ceph release: `ceph versions` shows the release of each daemon.
2. Check out the branch for that release, for example `git checkout v20.2.4`.
3. Read the documentation and build the binaries from that same branch.

Do not mix binaries and documentation from different branches.

## How to confirm the release of a build

The release a build targets is compiled in. Two checks show it:

- `croit-flashstore-osd --version` prints a line with the Ceph version and codename it was built for, for example `croit-flashstore-osd 21.2.0 umbrella (build ...)`.
- The file `services/osd/osd/src/version.rs` on the branch sets `CEPH_VERSION_SHORT` and `CEPH_RELEASE`.

The branch name is a label. The compiled version is the authority.

## What differs between branches

- The Ceph version the daemon speaks.
- The Ceph release it accepts from the cluster. The daemon refuses a cluster release outside its supported window.
- The documentation. The manual is kept in the `docs/` tree of the branch it describes. Pages on a branch that does not carry this tree are not available there.

Behavior that is the same on all branches is described in the explanation and reference pages. Behavior that differs is noted on the page that covers it.

## Documentation location

This manual lives in the `docs/` tree of each branch. The pages on a branch describe that branch. A page that names a Ceph release describes the release of the branch that contains it.

Related: [reference/exit-codes.md](../reference/exit-codes.md), [explanation/network-tiers.md](network-tiers.md).
