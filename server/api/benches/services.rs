// SPDX-License-Identifier: AGPL-3.0-only
//! Standalone service costs; these are not IME conversion timings.
use nextime_ai::assist::{Assistant, DeviceBudget};
use nextime_memory::Vault;
use nextime_security::{Manifest, SignedManifest, generate_key, sha256};
use std::{hint::black_box, time::Instant};

fn measure(name: &str, mut operation: impl FnMut()) -> serde_json::Value {
    for _ in 0..5 {
        operation();
    }
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        operation();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    serde_json::json!({"name": name, "samples": samples.len(), "unit": "ns",
        "p50": samples[49], "p95": samples[94], "max": samples[99]})
}

fn main() {
    let bytes = vec![42_u8; 32768];
    let key = generate_key();
    let signed = SignedManifest::sign(
        Manifest {
            format: 1,
            version: 1,
            dictionary_version: "benchmark".into(),
            issued_at: 100,
            expires_at: 200,
            bytes: bytes.len() as u64,
            sha256: sha256(&bytes),
            delta: None,
        },
        &key,
    )
    .unwrap();
    let public = key.verifying_key();
    let directory = tempfile::tempdir().unwrap();
    let mut vault = Vault::new(directory.path(), generate_key().to_bytes()).unwrap();
    vault.enable(true);
    vault.grant("synthetic", 60).unwrap();
    let mut assistant = Assistant::new(DeviceBudget::Low);
    assistant.enable(true);
    let results = vec![
        measure("sha256_32kib", || {
            black_box(sha256(black_box(&bytes)));
        }),
        measure("ed25519_manifest_verify", || {
            signed.verify(black_box(&public), 150).unwrap();
        }),
        measure("encrypted_memory_save_get_with_fsync", || {
            vault
                .save("synthetic", "sample", "合成データのみ", 100)
                .unwrap();
            black_box(vault.get("synthetic", "sample", 101).unwrap());
        }),
        measure("offline_absence_drafts", || {
            black_box(
                assistant
                    .absence_email("先生", "明日", "体調不良", "", false)
                    .unwrap(),
            );
        }),
    ];
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "scope": "local synthetic service benchmark; not conversion or A13 measurements",
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "results": results
        }))
        .unwrap()
    );
}
