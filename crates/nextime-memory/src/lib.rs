// SPDX-License-Identifier: AGPL-3.0-only
//! Local encrypted memory, disabled by default. Imports require per-contact consent.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub id: String,
    pub contact: String,
    pub text: String,
    pub saved_at: u64,
    pub expires_at: u64,
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn permission() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "memory consent required")
}
fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

pub struct Vault {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    enabled: bool,
    consent: BTreeMap<String, u64>,
}
impl Vault {
    pub fn new(root: impl AsRef<Path>, key: [u8; 32]) -> io::Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: root.as_ref().into(),
            key: Zeroizing::new(key),
            enabled: false,
            consent: BTreeMap::new(),
        })
    }
    pub fn enable(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.consent.clear();
        }
    }
    pub fn grant(&mut self, contact: &str, retention_seconds: u64) -> io::Result<()> {
        if !self.enabled {
            return Err(permission());
        }
        if !safe_id(contact) || !(60..=31_536_000).contains(&retention_seconds) {
            return Err(invalid("invalid contact or retention"));
        }
        self.consent.insert(contact.into(), retention_seconds);
        Ok(())
    }
    fn path(&self, contact: &str, id: &str) -> io::Result<PathBuf> {
        if !safe_id(contact) || !safe_id(id) {
            return Err(invalid("invalid memory id"));
        }
        Ok(self.root.join(format!("{contact}--{id}.memory")))
    }
    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new((&*self.key).into())
    }
    fn allowed(&self, contact: &str) -> io::Result<u64> {
        if !self.enabled {
            return Err(permission());
        }
        self.consent.get(contact).copied().ok_or_else(permission)
    }
    /// Call only with text supplied through an explicit import, never a global keyboard hook.
    pub fn save(&mut self, contact: &str, id: &str, text: &str, now: u64) -> io::Result<()> {
        let retention = self.allowed(contact)?;
        if text.is_empty() || text.len() > 16_384 || text.chars().any(|c| c == '\0') {
            return Err(invalid("invalid memory text"));
        }
        let memory = Memory {
            id: id.into(),
            contact: contact.into(),
            text: text.into(),
            saved_at: now,
            expires_at: now
                .checked_add(retention)
                .ok_or_else(|| invalid("expiry overflow"))?,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&memory)?);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let associated = format!("LUQNEXA-MEMORY-V1:{contact}:{id}");
        let ciphertext = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: associated.as_bytes(),
                },
            )
            .map_err(|_| invalid("memory encryption failed"))?;
        let mut bytes = b"NXMEM001".to_vec();
        bytes.extend_from_slice(&nonce);
        bytes.extend(ciphertext);
        let path = self.path(contact, id)?;
        let temporary = path.with_extension("new");
        // Serial use of a Vault is required; caller owns exclusive mutation access.
        fs::write(&temporary, bytes)?;
        fs::OpenOptions::new()
            .write(true)
            .open(&temporary)?
            .sync_all()?;
        // Encrypted destination can be replaced; a failed overwrite must report an error.
        nextime_update::atomic_replace(&temporary, &path)?;
        Ok(())
    }
    pub fn get(&mut self, contact: &str, id: &str, now: u64) -> io::Result<Option<Memory>> {
        self.allowed(contact)?;
        let path = self.path(contact, id)?;
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)?.len() > 32_768 {
            return Err(invalid("oversized memory"));
        }
        let raw = fs::read(&path)?;
        if raw.len() < 36 || &raw[..8] != b"NXMEM001" {
            return Err(invalid("invalid encrypted memory"));
        }
        let associated = format!("LUQNEXA-MEMORY-V1:{contact}:{id}");
        let plain = Zeroizing::new(
            self.cipher()
                .decrypt(
                    Nonce::from_slice(&raw[8..20]),
                    Payload {
                        msg: &raw[20..],
                        aad: associated.as_bytes(),
                    },
                )
                .map_err(|_| invalid("memory authentication failed"))?,
        );
        let memory: Memory = serde_json::from_slice(&plain)?;
        if memory.contact != contact || memory.id != id {
            return Err(invalid("memory identity mismatch"));
        }
        if now >= memory.expires_at {
            fs::remove_file(path)?;
            return Ok(None);
        }
        Ok(Some(memory))
    }
    pub fn delete(&self, contact: &str, id: &str) -> io::Result<()> {
        self.allowed(contact)?;
        let path = self.path(contact, id)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
    pub fn delete_all(&self) -> io::Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry.path().extension().is_some_and(|s| s == "memory")
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
    pub fn list(&mut self, contact: &str, now: u64) -> io::Result<Vec<Memory>> {
        self.allowed(contact)?;
        let mut memories = Vec::new();
        let prefix = format!("{contact}--");
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(id) = name
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(".memory"))
            {
                if let Some(memory) = self.get(contact, id, now)? {
                    memories.push(memory);
                }
            }
        }
        Ok(memories)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consent_encryption_expiry_and_correction() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::new(dir.path(), [7; 32]).unwrap();
        assert!(v.save("teacher", "one", "明日欠席", 100).is_err());
        v.enable(true);
        v.grant("teacher", 60).unwrap();
        v.save("teacher", "one", "明日欠席", 100).unwrap();
        assert!(
            !String::from_utf8_lossy(&fs::read(v.path("teacher", "one").unwrap()).unwrap())
                .contains("明日欠席")
        );
        assert!(v.get("friend", "one", 101).is_err());
        v.save("teacher", "one", "明日出席", 102).unwrap();
        assert_eq!(
            v.get("teacher", "one", 103).unwrap().unwrap().text,
            "明日出席"
        );
        assert!(v.get("teacher", "one", 162).unwrap().is_none());
    }
    #[test]
    fn detects_tampering_wrong_key_and_identity_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::new(dir.path(), [1; 32]).unwrap();
        v.enable(true);
        v.grant("a", 60).unwrap();
        v.save("a", "one", "private", 100).unwrap();
        let p = v.path("a", "one").unwrap();
        fs::copy(&p, v.path("a", "two").unwrap()).unwrap();
        assert!(v.get("a", "two", 101).is_err());
        let mut wrong = Vault::new(dir.path(), [2; 32]).unwrap();
        wrong.enable(true);
        wrong.grant("a", 60).unwrap();
        assert!(wrong.get("a", "one", 101).is_err());
        let mut raw = fs::read(&p).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        fs::write(p, raw).unwrap();
        assert!(v.get("a", "one", 101).is_err());
        v.delete_all().unwrap();
        assert!(v.list("a", 101).unwrap().is_empty());
    }
    #[test]
    fn disabling_revokes_all_grants() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::new(dir.path(), [1; 32]).unwrap();
        v.enable(true);
        v.grant("a", 60).unwrap();
        assert!(v.grant("../escape", 60).is_err());
        v.enable(false);
        v.enable(true);
        assert!(v.save("a", "one", "text", 0).is_err());
    }
}
