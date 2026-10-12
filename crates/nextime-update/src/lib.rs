// SPDX-License-Identifier: AGPL-3.0-only
//! Immutable versions with an atomic current/previous pointer. No networking.
use nexc_lite::FileDictionary;
use nextime_security::{MAX_DICTIONARY_BYTES, SignedManifest, VerifyingKey, file_sha256, invalid};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pointer {
    current: u64,
    previous: Option<u64>,
    highest: u64,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    pub base_sha256: String,
    pub prefix: u64,
    pub suffix: u64,
    pub insert: Vec<u8>,
}
impl Delta {
    pub fn between(base: &[u8], next: &[u8]) -> Self {
        let prefix = base.iter().zip(next).take_while(|(a, b)| a == b).count();
        let suffix = base[prefix..]
            .iter()
            .rev()
            .zip(next[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Self {
            base_sha256: nextime_security::sha256(base),
            prefix: prefix as u64,
            suffix: suffix as u64,
            insert: next[prefix..next.len() - suffix].to_vec(),
        }
    }
    pub fn apply(&self, base: impl AsRef<Path>, target: impl AsRef<Path>) -> io::Result<()> {
        if self.insert.len() > 16 * 1024 * 1024 || file_sha256(&base)? != self.base_sha256 {
            return Err(invalid("delta base or size mismatch"));
        }
        let mut input = File::open(base)?;
        let size = input.metadata()?.len();
        let ranges = self
            .prefix
            .checked_add(self.suffix)
            .ok_or_else(|| invalid("delta overflow"))?;
        let total = ranges
            .checked_add(self.insert.len() as u64)
            .ok_or_else(|| invalid("delta overflow"))?;
        if ranges > size || total > MAX_DICTIONARY_BYTES {
            return Err(invalid("invalid delta ranges"));
        }
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)?;
        io::copy(&mut Read::by_ref(&mut input).take(self.prefix), &mut out)?;
        out.write_all(&self.insert)?;
        input.seek(SeekFrom::Start(size - self.suffix))?;
        io::copy(&mut input.take(self.suffix), &mut out)?;
        out.sync_all()
    }
}
/// Windows replacement needs ReplaceExisting; deleting the old pointer first is unsafe.
pub fn atomic_replace(source: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let a: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, target)?;
        File::open(target.parent().ok_or_else(|| invalid("missing parent"))?)?.sync_all()?;
    }
    Ok(())
}
pub struct Store {
    root: PathBuf,
    key: VerifyingKey,
}
impl Store {
    pub fn new(root: impl AsRef<Path>, key: VerifyingKey) -> io::Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: root.as_ref().into(),
            key,
        })
    }
    fn pointer(&self) -> io::Result<Option<Pointer>> {
        let path = self.root.join("current.json");
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)?.len() > 1024 {
            return Err(invalid("oversized pointer"));
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }
    fn version_path(&self, version: u64) -> PathBuf {
        self.root
            .join(format!("version-{version}"))
            .join("base.nud")
    }
    fn check_version(&self, version: u64) -> io::Result<PathBuf> {
        let path = self.version_path(version);
        let meta = path.with_file_name("manifest.json");
        if fs::metadata(&meta)?.len() > 8192 {
            return Err(invalid("oversized installed manifest"));
        }
        let signed: SignedManifest = serde_json::from_slice(&fs::read(meta)?)?;
        signed.verify_stored(&self.key)?;
        if signed.manifest.version != version
            || fs::metadata(&path)?.len() != signed.manifest.bytes
            || file_sha256(&path)? != signed.manifest.sha256
        {
            return Err(invalid("installed dictionary damaged"));
        }
        FileDictionary::open_with_cache(&path, 0)?.validate_all()?;
        Ok(path)
    }
    pub fn current(&self) -> io::Result<Option<PathBuf>> {
        self.pointer()?
            .map(|p| self.check_version(p.current))
            .transpose()
    }
    pub fn current_version(&self) -> io::Result<Option<u64>> {
        Ok(self.pointer()?.map(|p| p.current))
    }
    fn commit(&self, pointer: &Pointer) -> io::Result<()> {
        let tmp = self.root.join("current.next");
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(&serde_json::to_vec(pointer)?)?;
        file.sync_all()?;
        drop(file);
        let result = atomic_replace(&tmp, &self.root.join("current.json"));
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
    /// Copy to a new version; failures never replace the active dictionary.
    pub fn install(
        &self,
        signed: &SignedManifest,
        artifact: &Path,
        delta: bool,
        now: u64,
    ) -> io::Result<()> {
        signed.verify(&self.key, now)?;
        // create_dir is a cross-process update lock, always released by this scope.
        let lock = self.root.join("update.lock");
        fs::create_dir(&lock)?;
        let _lock = DirectoryGuard(lock);
        let old = self.pointer()?;
        if old
            .as_ref()
            .is_some_and(|p| signed.manifest.version <= p.highest)
        {
            return Err(invalid("replayed or downgraded version"));
        }
        let directory = self
            .root
            .join(format!("version-{}", signed.manifest.version));
        fs::create_dir(&directory)?;
        let mut cleanup = DirectoryGuard(directory.clone());
        let staged = directory.join("base.nud");
        if delta {
            let metadata = signed
                .manifest
                .delta
                .as_ref()
                .ok_or_else(|| invalid("missing signed delta"))?;
            if fs::metadata(artifact)?.len() != metadata.bytes
                || file_sha256(artifact)? != metadata.sha256
            {
                return Err(invalid("delta integrity mismatch"));
            }
            let patch: Delta = serde_json::from_slice(&fs::read(artifact)?)?;
            if patch.base_sha256 != metadata.base_sha256 {
                return Err(invalid("delta base metadata mismatch"));
            }
            let base = self
                .current()?
                .ok_or_else(|| invalid("delta requires installed base"))?;
            patch.apply(base, &staged)?;
        } else {
            if fs::metadata(artifact)?.len() != signed.manifest.bytes {
                return Err(invalid("artifact size mismatch"));
            }
            let mut source = File::open(artifact)?;
            let mut target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged)?;
            io::copy(
                &mut Read::by_ref(&mut source).take(signed.manifest.bytes + 1),
                &mut target,
            )?;
            target.sync_all()?;
        }
        if file_sha256(&staged)? != signed.manifest.sha256 {
            return Err(invalid("dictionary SHA-256 mismatch"));
        }
        let dict = FileDictionary::open_with_cache(&staged, 0)?;
        dict.validate_all()?;
        drop(dict);
        let mut meta = File::create(directory.join("manifest.json"))?;
        meta.write_all(&serde_json::to_vec(signed)?)?;
        meta.sync_all()?;
        drop(meta);
        let committed = self.commit(&Pointer {
            current: signed.manifest.version,
            previous: old.as_ref().map(|p| p.current),
            highest: signed.manifest.version,
        });
        // A Unix directory fsync may fail after rename already changed the pointer.
        // Never remove a dictionary that the visible pointer now references.
        if committed.is_ok()
            || self.current_version().ok().flatten() == Some(signed.manifest.version)
        {
            cleanup.0 = PathBuf::new();
        }
        committed
    }
    pub fn rollback(&self) -> io::Result<()> {
        let lock = self.root.join("update.lock");
        fs::create_dir(&lock)?;
        let _lock = DirectoryGuard(lock);
        let old = self
            .pointer()?
            .ok_or_else(|| invalid("no active dictionary"))?;
        let previous = old.previous.ok_or_else(|| invalid("no rollback version"))?;
        self.check_version(previous)?;
        self.commit(&Pointer {
            current: previous,
            previous: Some(old.current),
            highest: old.highest,
        })
    }
}
struct DirectoryGuard(PathBuf);
impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nextime_dict::Entry;
    use nextime_security::{DeltaInfo, Manifest, generate_key, sha256};
    fn build(path: &Path, word: &str, version: u64) {
        nexc_max::build(
            path,
            vec![Entry {
                reading: "し".into(),
                surface: word.into(),
                part_of_speech: "noun".into(),
                frequency: 10,
            }],
            version,
        )
        .unwrap();
    }
    fn sign(
        path: &Path,
        version: u64,
        key: &nextime_security::SigningKey,
        delta: Option<DeltaInfo>,
    ) -> SignedManifest {
        SignedManifest::sign(
            Manifest {
                format: 1,
                version,
                dictionary_version: format!("v{version}"),
                issued_at: 10,
                expires_at: 100,
                bytes: fs::metadata(path).unwrap().len(),
                sha256: file_sha256(path).unwrap(),
                delta,
            },
            key,
        )
        .unwrap()
    }
    #[test]
    fn full_delta_rollback_and_replay_protection() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.nud");
        let b = dir.path().join("b.nud");
        build(&a, "詩", 1);
        build(&b, "市", 2);
        let key = generate_key();
        let store = Store::new(dir.path().join("store"), key.verifying_key()).unwrap();
        let first = sign(&a, 1, &key, None);
        store.install(&first, &a, false, 20).unwrap();
        assert_eq!(store.current_version().unwrap(), Some(1));
        let patch = Delta::between(&fs::read(&a).unwrap(), &fs::read(&b).unwrap());
        let raw = serde_json::to_vec(&patch).unwrap();
        let p = dir.path().join("delta.json");
        fs::write(&p, &raw).unwrap();
        let second = sign(
            &b,
            2,
            &key,
            Some(DeltaInfo {
                base_sha256: patch.base_sha256,
                sha256: sha256(&raw),
                bytes: raw.len() as u64,
            }),
        );
        store.install(&second, &p, true, 20).unwrap();
        assert_eq!(
            file_sha256(store.current().unwrap().unwrap()).unwrap(),
            file_sha256(&b).unwrap()
        );
        store.rollback().unwrap();
        assert_eq!(store.current_version().unwrap(), Some(1));
        assert!(store.install(&second, &b, false, 20).is_err());
        // Existing offline content remains readable after release expiry.
        assert!(store.current().unwrap().is_some());
    }
    #[test]
    fn failed_update_keeps_previous_and_can_retry_same_version() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.nud");
        let b = dir.path().join("b.nud");
        build(&a, "詩", 1);
        build(&b, "市", 2);
        let key = generate_key();
        let store = Store::new(dir.path().join("store"), key.verifying_key()).unwrap();
        store
            .install(&sign(&a, 1, &key, None), &a, false, 20)
            .unwrap();
        let signed = sign(&b, 2, &key, None);
        fs::write(&b, b"corrupt").unwrap();
        assert!(store.install(&signed, &b, false, 20).is_err());
        assert_eq!(store.current_version().unwrap(), Some(1));
        fs::remove_file(&b).unwrap();
        build(&b, "市", 2);
        store.install(&signed, &b, false, 20).unwrap();
        assert_eq!(store.current_version().unwrap(), Some(2));
    }
    #[test]
    fn wrong_key_expiry_and_invalid_nud_are_never_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.nud");
        fs::write(&path, b"not-a-dictionary").unwrap();
        let key = generate_key();
        let signed = sign(&path, 1, &key, None);
        let store = Store::new(dir.path().join("store"), key.verifying_key()).unwrap();
        assert!(store.install(&signed, &path, false, 20).is_err());
        assert!(store.current().unwrap().is_none());
        assert!(store.install(&signed, &path, false, 100).is_err());
        let wrong = Store::new(dir.path().join("other"), generate_key().verifying_key()).unwrap();
        assert!(wrong.install(&signed, &path, false, 20).is_err());
    }
    #[test]
    fn rejects_delta_wrong_base_and_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        fs::write(&base, b"abc").unwrap();
        let mut delta = Delta::between(b"abc", b"abd");
        delta.prefix = u64::MAX;
        assert!(delta.apply(&base, dir.path().join("target")).is_err());
        delta.prefix = 0;
        delta.base_sha256 = sha256(b"other");
        assert!(delta.apply(&base, dir.path().join("target")).is_err());
    }
    #[test]
    fn exclusive_update_lock_and_corrupted_pointer_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.nud");
        build(&a, "詩", 1);
        let key = generate_key();
        let store = Store::new(dir.path().join("store"), key.verifying_key()).unwrap();
        fs::create_dir(store.root.join("update.lock")).unwrap();
        assert!(
            store
                .install(&sign(&a, 1, &key, None), &a, false, 20)
                .is_err()
        );
        fs::remove_dir(store.root.join("update.lock")).unwrap();
        store
            .install(&sign(&a, 1, &key, None), &a, false, 20)
            .unwrap();
        fs::write(store.root.join("current.json"), b"bad").unwrap();
        assert!(store.current().is_err());
    }
}
