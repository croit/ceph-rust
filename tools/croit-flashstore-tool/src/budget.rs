// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `croit-flashstore-tool hugepage-budget --id N [--cluster C] [--conf F] [--format plain|json|json-pretty]`: the
//! hugepage budget (MB) of `osd.N` from the ceph conf, resolved by [`osddir::hugepages_need_mb`], the same resolver
//! `activate` checks against and the daemon is started with (`--mem`). The root prep unit reserves exactly this
//! budget instead of parsing the conf itself. Read-only. Exit: 0 ok, 2 usage, 3 conf unreadable or budget invalid.
use outfmt::Format;
use serde_json::json;

pub fn run(a: &[String], f: Format) -> i32 {
    match budget(a) {
        Ok((id, mb)) => {
            if f.is_json() {
                println!("{}", f.doc(&json!({"osd_id": id, "hugepages_mb": mb})));
            } else {
                println!("{mb}");
            }
            0
        }
        Err((c, m)) => {
            eprintln!("croit-flashstore-tool hugepage-budget: {m}");
            c
        }
    }
}

fn budget(a: &[String]) -> Result<(i64, u64), (i32, String)> {
    let id = a
        .iter()
        .position(|x| x == "--id")
        .and_then(|i| a.get(i + 1))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n >= 0);
    let Some(id) = id else {
        return Err((
            2,
            "usage: hugepage-budget --id N [--cluster C] [--conf F] [--format plain|json|json-pretty]".into(),
        ));
    };
    let cl = osddir::cluster_from_args(a).map_err(|e| (2, e))?;
    let path = osddir::conf_file(a, &cl).map_err(|e| (2, e))?;
    let conf = osddir::Conf::load(&path).map_err(|e| (3, e))?;
    let mb = osddir::hugepages_need_mb(&conf.for_osd(id)).map_err(|e| (3, e))?;
    Ok((id, mb))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_conf(body: &str, f: impl FnOnce(&str)) {
        let d =
            std::env::temp_dir().join(format!("hp-budget-{}-{}", std::process::id(), body.len()));
        std::fs::write(&d, body).unwrap();
        f(d.to_str().unwrap());
        std::fs::remove_file(&d).unwrap();
    }

    fn args(conf: &str) -> Vec<String> {
        ["--id", "1", "--conf", conf].map(String::from).to_vec()
    }

    /// NT-runtimeenv-03: the prep unit reserved a different budget than the daemon used (`4G` broke the shell
    /// arithmetic, the `flashstore_mem` alias was ignored). One resolver: suffix, alias, section precedence, conflicts.
    #[test]
    fn budget_is_the_daemon_resolver() {
        with_conf("[osd.1]\nflashstore_hugepages_mb = 4G\n", |c| {
            assert_eq!(budget(&args(c)), Ok((1, 4096)));
        });
        with_conf("[osd]\nflashstore_mem = 4096\n", |c| {
            assert_eq!(budget(&args(c)), Ok((1, 4096)));
        });
        with_conf(
            "[global]\nflashstore_hugepages_mb = 1024\n[osd.2]\nflashstore_hugepages_mb = 8192\n",
            |c| {
                assert_eq!(budget(&args(c)), Ok((1, 1024)));
            },
        );
        with_conf("[osd.1]\n", |c| {
            assert_eq!(budget(&args(c)), Ok((1, osddir::DEFAULT_HUGEPAGES_MB)));
        });
        with_conf(
            "[osd.1]\nflashstore_hugepages_mb = 2048\nflashstore_mem = 4096\n",
            |c| {
                assert_eq!(budget(&args(c)).unwrap_err().0, 3);
            },
        );
        with_conf("[osd.1]\nflashstore_hugepages_mb = 4Gx\n", |c| {
            assert_eq!(budget(&args(c)).unwrap_err().0, 3);
        });
        assert_eq!(budget(&args("/nonexistent/ceph.conf")).unwrap_err().0, 3);
        assert_eq!(budget(&["--conf".into(), "/x".into()]).unwrap_err().0, 2);
    }
}
