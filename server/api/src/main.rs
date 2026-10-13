// SPDX-License-Identifier: AGPL-3.0-only
use nextime_security::{
    DeltaInfo, Manifest, SignedManifest, SigningKey, VerifyingKey, file_sha256, generate_key,
};
use nextime_update::{Delta, Store};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};
fn public(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let raw: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&raw)?)
}
fn write_new(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(action) = args.first().map(String::as_str) else {
        help();
        return Ok(());
    };
    match action {
        "keygen" if args.len() == 2 => {
            let root = Path::new(&args[1]);
            fs::create_dir_all(root)?;
            let key = generate_key();
            write_new(&root.join("signing.key"), &key.to_bytes(), true)?;
            write_new(
                &root.join("public.key"),
                &key.verifying_key().to_bytes(),
                false,
            )?;
            println!(
                "Created private signing.key and public public.key. Keep signing.key outside source control."
            );
        }
        "publish" if (4..=5).contains(&args.len()) => {
            let source = Path::new(&args[1]);
            let root = Path::new(&args[2]);
            let version: u64 = args[3].parse()?;
            let private = env::var("LUQNEXA_SIGNING_KEY_FILE")
                .map_err(|_| "set LUQNEXA_SIGNING_KEY_FILE to a protected signing-key path")?;
            let raw: [u8; 32] = fs::read(private)?
                .try_into()
                .map_err(|_| "signing key must be 32 bytes")?;
            let key = SigningKey::from_bytes(&raw);
            nexc_lite::FileDictionary::open_with_cache(source, 0)?.validate_all()?;
            fs::create_dir(root)?;
            fs::copy(source, root.join("base.nud"))?;
            OpenOptions::new()
                .write(true)
                .open(root.join("base.nud"))?
                .sync_all()?;
            let published = root.join("base.nud");
            nexc_lite::FileDictionary::open_with_cache(&published, 0)?.validate_all()?;
            let delta = if let Some(base) = args.get(4) {
                if fs::metadata(base)?.len() > 64 * 1024 * 1024
                    || fs::metadata(&published)?.len() > 64 * 1024 * 1024
                {
                    return Err("delta builder currently limited to 64 MiB; publish full release without BASE".into());
                }
                let patch = Delta::between(&fs::read(base)?, &fs::read(&published)?);
                if patch.insert.len() > 16 * 1024 * 1024 {
                    return Err(
                        "delta insert exceeds 16 MiB; publish full release without BASE".into(),
                    );
                }
                let bytes = serde_json::to_vec(&patch)?;
                write_new(&root.join("delta.json"), &bytes, false)?;
                Some(DeltaInfo {
                    base_sha256: patch.base_sha256,
                    sha256: nextime_security::sha256(&bytes),
                    bytes: bytes.len() as u64,
                })
            } else {
                None
            };
            let now = luqnexa_server::now();
            let manifest = Manifest {
                format: 1,
                version,
                dictionary_version: format!("release-{version}"),
                issued_at: now,
                expires_at: now + 86400 * 30,
                bytes: fs::metadata(&published)?.len(),
                sha256: file_sha256(&published)?,
                delta,
            };
            let signed = SignedManifest::sign(manifest, &key)?;
            write_new(
                &root.join("manifest.json"),
                &serde_json::to_vec_pretty(&signed)?,
                false,
            )?;
            println!("Published signed release {version}; offline validation passed.");
        }
        "serve" if (3..=4).contains(&args.len()) => {
            let token = env::var("LUQNEXA_SUBMISSION_TOKEN")
                .map_err(|_| "set LUQNEXA_SUBMISSION_TOKEN (32+ ASCII bytes)")?;
            let state = luqnexa_server::ApiState::new(&args[1], public(&args[2])?, &token)?;
            let address: std::net::SocketAddr = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("127.0.0.1:8088")
                .parse()?;
            if !address.ip().is_loopback() {
                return Err("prototype binds loopback only; configure a reviewed HTTPS deployment separately".into());
            }
            let listener = tokio::net::TcpListener::bind(address).await?;
            println!("http://{}", listener.local_addr()?);
            axum::serve(listener, luqnexa_server::router(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        "install" if args.len() == 6 => {
            let store = Store::new(&args[1], public(&args[2])?)?;
            let meta = Path::new(&args[3]);
            if fs::metadata(meta)?.len() > 8192 {
                return Err("oversized manifest".into());
            }
            let signed: SignedManifest = serde_json::from_slice(&fs::read(meta)?)?;
            let delta = match args[5].as_str() {
                "full" => false,
                "delta" => true,
                _ => return Err("kind must be full or delta".into()),
            };
            store.install(&signed, Path::new(&args[4]), delta, luqnexa_server::now())?;
            println!(
                "Verified and activated release {} in the isolated store; running IME unchanged.",
                signed.manifest.version
            );
        }
        "rollback" if args.len() == 3 => {
            Store::new(&args[1], public(&args[2])?)?.rollback()?;
            println!("Isolated store rolled back; replay high-water mark retained.");
        }

        _ => help(),
    }
    Ok(())
}
fn help() {
    println!(
        "Luqnexa Phase 4/5 prototypes\nkeygen DIR\npublish SOURCE.nud NEW_RELEASE_DIR VERSION [BASE.nud]\nserve RELEASE_DIR PUBLIC.key [127.0.0.1:PORT]\ninstall ISOLATED_STORE PUBLIC.key MANIFEST.json ARTIFACT full|delta\nrollback ISOLATED_STORE PUBLIC.key\nNo automatic cloud requests, app history collection, IME installation or sending."
    );
}
