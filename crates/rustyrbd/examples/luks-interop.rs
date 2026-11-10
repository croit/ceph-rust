// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Independent cryptsetup interchange fixture; never prints key material.
use rustyrbd::luks;
use std::{fs, io::Write};
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (format, args) = outfmt::extract(args, false)?;
    if args.len() != 5 {
        return Err("usage: luks-interop create1|create2|parse image key-file pass-file aes128|aes256 [--format plain|json|json-pretty]".into());
    }
    let passphrase = fs::read(&args[3])?;
    match args[0].as_str() {
        "create1" | "create2" => {
            let alg = match args[4].as_str() {
                "aes128" => luks::ALG_AES128,
                "aes256" => luks::ALG_AES256,
                _ => return Err("invalid algorithm".into()),
            };
            let (header, load) = match args[0].as_str() {
                "create1" => luks::luks1_create(&passphrase, alg),
                _ => luks::luks2_create(&passphrase, alg),
            }
            .map_err(|_| "format failed")?;
            let mut image = fs::File::create(&args[1])?;
            image.set_len(32 * 1024 * 1024)?;
            image.write_all(&header)?;
            fs::write(&args[2], &*load.volume_key)?;
        }
        "parse" => {
            let header = fs::read(&args[1])?;
            let load = match luks::detect_format(&header) {
                Some(luks::FORMAT_LUKS1) => luks::luks1_parse(&header, &passphrase),
                _ => luks::luks2_parse(&header, &passphrase),
            }
            .map_err(|_| "unlock failed")?;
            if *load.volume_key != fs::read(&args[2])? {
                return Err("volume key mismatch".into());
            }
        }
        _ => return Err("invalid operation".into()),
    }
    if format == outfmt::Format::Plain {
        println!("luks-interop status=pass");
    } else {
        println!("{}", format.doc(&serde_json::json!({"status":"pass"})));
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
