// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};

use keyring::Entry;
use rand::RngCore;
use std::sync::OnceLock;

/// Persist the base64-encoded encryption key to a local file with restrictive
/// permissions (0600 file, 0700 directory). Used only as a fallback when the OS
/// keyring is unavailable.
fn save_key_file(path: &std::path::Path, b64_key: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                eprintln!("Warning: failed to set secure permissions on key directory: {e}");
            }
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(b64_key.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, b64_key)?;
    }
    Ok(())
}

/// Abstraction over OS keyring operations for testability.
trait KeyringProvider {
    /// Attempt to read the stored password. Returns `Err(NoEntry)` if
    /// no entry exists, or another `keyring::Error` on platform failure.
    fn get_password(&self) -> Result<String, keyring::Error>;
    /// Attempt to store a password in the keyring.
    fn set_password(&self, password: &str) -> Result<(), keyring::Error>;
}

/// Production keyring implementation wrapping an optional `keyring::Entry`.
/// `None` means `Entry::new` itself failed (no backend available).
struct OsKeyring(Option<Entry>);

impl OsKeyring {
    fn new(service: &str, user: &str) -> Self {
        Self(Entry::new(service, user).ok())
    }
}

impl KeyringProvider for OsKeyring {
    fn get_password(&self) -> Result<String, keyring::Error> {
        match &self.0 {
            Some(entry) => entry.get_password(),
            None => Err(keyring::Error::NoEntry),
        }
    }

    fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
        match &self.0 {
            Some(entry) => entry.set_password(password),
            None => Err(keyring::Error::NoEntry),
        }
    }
}

/// Core key-resolution logic, separated from caching for testability.
///
/// Priority order:
/// 1. Keyring entry (authoritative when available)
/// 2. Local `.encryption_key` file (persistent fallback)
/// 3. Generate a new random 256-bit key
///
/// The file is **never deleted** — it serves as a safe fallback for
/// environments where the keyring is ephemeral (e.g. Docker containers).
fn resolve_key(
    provider: &dyn KeyringProvider,
    key_file: &std::path::Path,
) -> anyhow::Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // --- 1. Try keyring -------------------------------------------------
    match provider.get_password() {
        Ok(b64_key) => {
            if let Ok(decoded) = STANDARD.decode(&b64_key) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Ok(arr);
                }
            }
            // Keyring contained invalid data — fall through to file/generate.
        }
        Err(keyring::Error::NoEntry) => {
            // Keyring is reachable but empty — check file, then generate.

            // 1a. Prefer an existing file key.
            if let Some(key) = read_key_file(key_file) {
                // Best-effort: copy file key into keyring for future runs.
                let _ = provider.set_password(&STANDARD.encode(key));
                return Ok(key);
            }

            // 1b. Generate a new key.
            let key = generate_random_key();
            let b64_key = STANDARD.encode(key);

            // Try keyring first.
            let _ = provider.set_password(&b64_key);

            // Always persist to file as a durable fallback. This ensures
            // the key survives keyring loss (e.g. Docker container restart).
            save_key_file(key_file, &b64_key)?;

            return Ok(key);
        }
        Err(e) => {
            eprintln!("Warning: keyring access failed, falling back to file storage: {e}");
        }
    }

    // --- 2. File fallback ------------------------------------------------
    if let Some(key) = read_key_file(key_file) {
        return Ok(key);
    }

    // --- 3. Generate new key, save to file -------------------------------
    let key = generate_random_key();
    let b64_key = STANDARD.encode(key);
    save_key_file(key_file, &b64_key)?;
    Ok(key)
}

/// Read and decode a base64-encoded 256-bit key from a file.
fn read_key_file(path: &std::path::Path) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64_key = std::fs::read_to_string(path).ok()?;
    let decoded = STANDARD.decode(b64_key.trim()).ok()?;
    if decoded.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Some(arr)
    } else {
        None
    }
}

/// Generate a random 256-bit key.
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Returns the encryption key derived from the OS keyring, or falls back to a local file.
/// Generates a random 256-bit key and stores it securely if it doesn't exist.
fn get_or_create_key() -> anyhow::Result<[u8; 32]> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();

    if let Some(key) = KEY.get() {
        return Ok(*key);
    }

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());

    let key_file = crate::auth_commands::config_dir().join(".encryption_key");
    let provider = OsKeyring::new("gws-cli", &username);

    let key = resolve_key(&provider, &key_file)?;

    // Cache for subsequent calls within this process.
    if KEY.set(key).is_ok() {
        Ok(key)
    } else {
        Ok(*KEY
            .get()
            .expect("key must be initialized if OnceLock::set() failed"))
    }
}

/// Encrypts plaintext bytes using AES-256-GCM with a machine-derived key.
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = get_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data produced by `encrypt()`.
pub fn decrypt(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("Encrypted data too short");
    }

    let key = get_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;

    let nonce = Nonce::from_slice(&data[..12]);
    let plaintext = cipher.decrypt(nonce, &data[12..]).map_err(|_| {
        anyhow::anyhow!(
            "Decryption failed. Credentials may have been created on a different machine. \
                 Run `gws auth logout` and `gws auth login` to re-authenticate."
        )
    })?;

    Ok(plaintext)
}

/// Returns the path for encrypted credentials.
pub fn encrypted_credentials_path() -> PathBuf {
    crate::auth_commands::config_dir().join("credentials.enc")
}

/// Saves credentials JSON to an encrypted file.
pub fn save_encrypted(json: &str) -> anyhow::Result<PathBuf> {
    let path = encrypted_credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                eprintln!(
                    "Warning: failed to set directory permissions on {}: {e}",
                    parent.display()
                );
            }
        }
    }

    let encrypted = encrypt(json.as_bytes())?;

    // Write atomically via a sibling .tmp file + rename so the credentials
    // file is never left in a corrupt partial-write state on crash/Ctrl-C.
    crate::fs_util::atomic_write(&path, &encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to write credentials: {e}"))?;

    // Set permissions to 600 on Unix (contains secrets)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "Warning: failed to set file permissions on {}: {e}",
                path.display()
            );
        }
    }

    Ok(path)
}

/// Loads and decrypts credentials JSON from a specific path.
pub fn load_encrypted_from_path(path: &std::path::Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    let plaintext = decrypt(&data)?;
    Ok(String::from_utf8(plaintext)?)
}

/// Loads and decrypts credentials JSON from the default encrypted file.
pub fn load_encrypted() -> anyhow::Result<String> {
    load_encrypted_from_path(&encrypted_credentials_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Describes what `get_password` / `set_password` should return,
    /// without storing `keyring::Error` (which is not `Clone`).
    #[derive(Clone)]
    enum MockState {
        Ok(String),
        NoEntry,
        PlatformError,
    }

    /// Mock keyring for testing `resolve_key()` without OS dependencies.
    struct MockKeyring {
        get_state: MockState,
        set_succeeds: bool,
        /// Tracks the last value passed to `set_password`.
        last_set: RefCell<Option<String>>,
    }

    impl MockKeyring {
        /// Keyring that returns the given password on `get_password`.
        fn with_password(b64: &str) -> Self {
            Self {
                get_state: MockState::Ok(b64.to_string()),
                set_succeeds: true,
                last_set: RefCell::new(None),
            }
        }

        /// Keyring that returns `NoEntry` on `get_password`.
        fn no_entry() -> Self {
            Self {
                get_state: MockState::NoEntry,
                set_succeeds: true,
                last_set: RefCell::new(None),
            }
        }

        /// Keyring that returns a platform error on `get_password`.
        fn platform_error() -> Self {
            Self {
                get_state: MockState::PlatformError,
                set_succeeds: true,
                last_set: RefCell::new(None),
            }
        }

        /// Configure `set_password` to fail.
        fn with_set_failure(mut self) -> Self {
            self.set_succeeds = false;
            self
        }
    }

    impl KeyringProvider for MockKeyring {
        fn get_password(&self) -> Result<String, keyring::Error> {
            match &self.get_state {
                MockState::Ok(s) => Ok(s.clone()),
                MockState::NoEntry => Err(keyring::Error::NoEntry),
                MockState::PlatformError => {
                    Err(keyring::Error::PlatformFailure("mock: no backend".into()))
                }
            }
        }

        fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
            *self.last_set.borrow_mut() = Some(password.to_string());
            if self.set_succeeds {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }
    }

    /// Helper: write a known key to a temp file, return (dir, path, key_bytes).
    fn write_test_key(dir: &std::path::Path) -> ([u8; 32], std::path::PathBuf) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let key = [42u8; 32];
        let b64 = STANDARD.encode(key);
        let path = dir.join(".encryption_key");
        std::fs::write(&path, &b64).unwrap();
        (key, path)
    }

    // ---- resolve_key tests ----

    #[test]
    fn keyring_ok_returns_keyring_key() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(".encryption_key");

        let expected_key = [7u8; 32];
        let mock = MockKeyring::with_password(&STANDARD.encode(expected_key));

        let result = resolve_key(&mock, &key_file).unwrap();
        assert_eq!(result, expected_key);
    }

    #[test]
    fn keyring_ok_file_exists_keeps_file() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let (_, key_file) = write_test_key(dir.path());

        let keyring_key = [7u8; 32];
        let mock = MockKeyring::with_password(&STANDARD.encode(keyring_key));

        let result = resolve_key(&mock, &key_file).unwrap();
        assert_eq!(result, keyring_key, "keyring key should be authoritative");
        assert!(key_file.exists(), "file must NOT be deleted");
    }

    #[test]
    fn no_entry_file_exists_returns_file_key_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        let (expected_key, key_file) = write_test_key(dir.path());

        let mock = MockKeyring::no_entry();
        let result = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(result, expected_key, "should return the file key");
        assert!(
            key_file.exists(),
            "file must NOT be deleted after migration"
        );
        assert!(
            mock.last_set.borrow().is_some(),
            "should attempt to copy key into keyring"
        );
    }

    #[test]
    fn no_entry_no_file_keyring_set_succeeds_still_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(".encryption_key");

        let mock = MockKeyring::no_entry();
        let key = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(key.len(), 32);
        assert!(
            key_file.exists(),
            "file must be created as durable fallback even when keyring succeeds"
        );
        // The file should contain the same key.
        let file_key = read_key_file(&key_file).unwrap();
        assert_eq!(key, file_key);
    }

    #[test]
    fn no_entry_no_file_keyring_set_fails_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(".encryption_key");

        let mock = MockKeyring::no_entry().with_set_failure();
        let key = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(key.len(), 32);
        assert!(key_file.exists(), "file must be created as fallback");
        let file_key = read_key_file(&key_file).unwrap();
        assert_eq!(key, file_key);
    }

    #[test]
    fn keyring_platform_error_file_exists_returns_file_key() {
        let dir = tempfile::tempdir().unwrap();
        let (expected_key, key_file) = write_test_key(dir.path());

        let mock = MockKeyring::platform_error();
        let result = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(result, expected_key);
        assert!(key_file.exists());
    }

    #[test]
    fn keyring_platform_error_no_file_generates_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(".encryption_key");

        let mock = MockKeyring::platform_error();
        let key = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(key.len(), 32);
        assert!(key_file.exists(), "file must be created");
        let file_key = read_key_file(&key_file).unwrap();
        assert_eq!(key, file_key);
    }

    #[test]
    fn resolve_key_is_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(".encryption_key");

        // First call: no keyring, no file → generates key.
        let mock = MockKeyring::platform_error();
        let key1 = resolve_key(&mock, &key_file).unwrap();

        // Second call: same file exists → returns same key.
        let key2 = resolve_key(&mock, &key_file).unwrap();
        assert_eq!(key1, key2, "must return the same key on subsequent calls");
    }

    #[test]
    fn keyring_invalid_data_falls_through_to_file() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let (expected_key, key_file) = write_test_key(dir.path());

        // Keyring returns invalid (wrong length) data.
        let mock = MockKeyring::with_password(&STANDARD.encode([1u8; 16]));
        let result = resolve_key(&mock, &key_file).unwrap();

        assert_eq!(
            result, expected_key,
            "should fall through to file when keyring data is invalid"
        );
    }

    // ---- read_key_file tests ----

    #[test]
    fn read_key_file_valid() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let key = [99u8; 32];
        std::fs::write(&path, STANDARD.encode(key)).unwrap();
        assert_eq!(read_key_file(&path), Some(key));
    }

    #[test]
    fn read_key_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_key_file(&dir.path().join("nonexistent")), None);
    }

    #[test]
    fn read_key_file_wrong_length() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, STANDARD.encode([1u8; 16])).unwrap();
        assert_eq!(read_key_file(&path), None);
    }

    #[test]
    fn read_key_file_invalid_base64() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "not-valid-base64!!!").unwrap();
        assert_eq!(read_key_file(&path), None);
    }

    // ---- Existing encrypt/decrypt tests ----

    #[test]
    fn get_or_create_key_is_deterministic() {
        let key1 = get_or_create_key().unwrap();
        let key2 = get_or_create_key().unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn get_or_create_key_produces_256_bits() {
        let key = get_or_create_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let plaintext = b"hello, world!";
        let encrypted = encrypt(plaintext).expect("encryption should succeed");
        assert_ne!(&encrypted, plaintext);
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty() {
        let plaintext = b"";
        let encrypted = encrypt(plaintext).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_short_data() {
        let result = decrypt(&[0u8; 11]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let encrypted = encrypt(b"secret data").expect("encryption should succeed");
        let mut tampered = encrypted.clone();
        if tampered.len() > 12 {
            tampered[12] ^= 0xFF;
        }
        let result = decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn each_encryption_produces_different_output() {
        let plaintext = b"same input";
        let enc1 = encrypt(plaintext).expect("encryption should succeed");
        let enc2 = encrypt(plaintext).expect("encryption should succeed");
        assert_ne!(enc1, enc2);
        let dec1 = decrypt(&enc1).unwrap();
        let dec2 = decrypt(&enc2).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, plaintext);
    }
}
