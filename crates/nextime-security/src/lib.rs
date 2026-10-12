// SPDX-License-Identifier: AGPL-3.0-only
//! Signed release metadata. Trust keys must be configured outside downloaded data.
use ed25519_dalek::{Signature, Signer};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub const MAX_DICTIONARY_BYTES: u64 = 1024 * 1024 * 1024;
pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn file_sha256(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeltaInfo {
    pub base_sha256: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub version: u64,
    pub dictionary_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub bytes: u64,
    pub sha256: String,
    pub delta: Option<DeltaInfo>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub signature: String,
}
impl Manifest {
    fn validate(&self) -> io::Result<()> {
        let hash_ok = |s: &str| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit());
        if self.format != 1
            || self.version == 0
            || self.bytes == 0
            || self.bytes > MAX_DICTIONARY_BYTES
            || !hash_ok(&self.sha256)
            || self.issued_at >= self.expires_at
            || self.dictionary_version.is_empty()
            || self.dictionary_version.len() > 64
        {
            return Err(invalid("invalid manifest"));
        }
        if let Some(d) = &self.delta {
            if !hash_ok(&d.sha256)
                || !hash_ok(&d.base_sha256)
                || d.bytes == 0
                || d.bytes > 64 * 1024 * 1024
            {
                return Err(invalid("invalid delta metadata"));
            }
        }
        Ok(())
    }
    fn message(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = b"LUQNEXA-DICTIONARY-MANIFEST-V1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }
}
impl SignedManifest {
    pub fn sign(manifest: Manifest, key: &SigningKey) -> io::Result<Self> {
        let signature = hex::encode(key.sign(&manifest.message()?).to_bytes());
        Ok(Self {
            manifest,
            signature,
        })
    }
    pub fn verify(&self, key: &VerifyingKey, now: u64) -> io::Result<()> {
        self.verify_stored(key)?;
        if now < self.manifest.issued_at || now >= self.manifest.expires_at {
            return Err(invalid("manifest not valid at this time"));
        }
        Ok(())
    }
    /// Previously installed data remains usable offline after metadata expiry.
    pub fn verify_stored(&self, key: &VerifyingKey) -> io::Result<()> {
        if self.signature.len() != 128 {
            return Err(invalid("invalid signature length"));
        }
        let raw = hex::decode(&self.signature).map_err(|_| invalid("invalid signature"))?;
        let signature = Signature::from_slice(&raw).map_err(|_| invalid("invalid signature"))?;
        key.verify_strict(&self.manifest.message()?, &signature)
            .map_err(|_| invalid("untrusted signature"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Manifest {
        Manifest {
            format: 1,
            version: 1,
            dictionary_version: "2026.10.12".into(),
            issued_at: 100,
            expires_at: 200,
            bytes: 4,
            sha256: sha256(b"test"),
            delta: None,
        }
    }
    #[test]
    fn rejects_tampering_wrong_key_and_expiry() {
        let key = generate_key();
        let signed = SignedManifest::sign(sample(), &key).unwrap();
        signed.verify(&key.verifying_key(), 150).unwrap();
        assert!(signed.verify(&generate_key().verifying_key(), 150).is_err());
        assert!(signed.verify(&key.verifying_key(), 200).is_err());
        assert!(signed.verify(&key.verifying_key(), 99).is_err());
        let mut tampered = signed.clone();
        tampered.manifest.version = 2;
        assert!(tampered.verify(&key.verifying_key(), 150).is_err());
        signed.verify_stored(&key.verifying_key()).unwrap();
    }
    #[test]
    fn hash_known_vector() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
