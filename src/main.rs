//! RustPw - A secure password manager built with Rust and Iced
//!
//! Features:
//! - AES-256-GCM encrypted vault files
//! - Multiple categories with tabs
//! - Password generation with strength calculation
//! - Password visibility toggle
//! - Secure clipboard operations with auto-clear
//! - Search functionality
//! - Auto-lock after inactivity

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ctr::cipher::StreamCipher;
use chrono::Utc;
use iced::widget::{
    button, checkbox, column, container, horizontal_rule, horizontal_space, image, progress_bar,
    row, scrollable, text, text_input, tooltip, vertical_space, Column, Row, Tooltip,
};
use iced::widget::text_input::Id as TextInputId;
use iced::{
    alignment, keyboard, time, widget, window, Color, Element, Font, Length, Subscription, Task, Theme,
};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================
const APP_NAME: &str = "RustPw";
const APP_VERSION: &str = "1.0.0";
const WINDOW_WIDTH: u32 = 1024;
const WINDOW_HEIGHT: u32 = 768;
const VAULT_FILE_EXTENSION: &str = "rustpw";
const CONFIG_FILE_NAME: &str = "rustpw.conf";

// Vault file format version
const VAULT_VERSION: u8 = 1;

// Color scheme (matching Python PyPigeon theme)
const COLOR_BG_DARK: Color = Color::from_rgb(0.094, 0.090, 0.207); // #181735
const COLOR_BG_TITLE: Color = Color::from_rgb(0.059, 0.059, 0.302); // #0F0F4D
const COLOR_BG_BLACK: Color = Color::from_rgb(0.0, 0.0, 0.0); // #000000
const COLOR_ACCENT_YELLOW: Color = Color::from_rgb(1.0, 1.0, 0.0); // yellow
const COLOR_ACCENT_CYAN: Color = Color::from_rgb(0.0, 1.0, 1.0); // cyan
const COLOR_ACCENT_GREEN: Color = Color::from_rgb(0.0, 1.0, 0.0); // #00FF00
const COLOR_TEXT_WHITE: Color = Color::from_rgb(1.0, 1.0, 1.0); // white
const COLOR_ACCENT_ORANGE: Color = Color::from_rgb(1.0, 0.6, 0.0); // #FF9900
const COLOR_ACCENT_PURPLE: Color = Color::from_rgb(0.8, 0.4, 1.0); // #CC66FF
const COLOR_ACCENT_RED: Color = Color::from_rgb(1.0, 0.4, 0.4); // #FF6666
const COLOR_HOVER: Color = Color::from_rgb(0.184, 0.184, 0.427); // #2F2F6D
const COLOR_TEXT_DIM: Color = Color::from_rgb(0.5, 0.5, 0.5); // dimmed gray for disabled

// Special characters for password generation
const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

// Text input IDs for focus management
fn id_vault_path() -> TextInputId { TextInputId::new("vault_path") }
fn id_passphrase() -> TextInputId { TextInputId::new("passphrase") }
fn id_confirm_passphrase() -> TextInputId { TextInputId::new("confirm_passphrase") }
fn id_entry_name() -> TextInputId { TextInputId::new("entry_name") }
fn id_entry_username() -> TextInputId { TextInputId::new("entry_username") }
fn id_entry_password() -> TextInputId { TextInputId::new("entry_password") }
fn id_entry_url() -> TextInputId { TextInputId::new("entry_url") }
fn id_entry_notes() -> TextInputId { TextInputId::new("entry_notes") }
fn id_category_name() -> TextInputId { TextInputId::new("category_name") }
fn id_search() -> TextInputId { TextInputId::new("search") }

// ============================================================================
// Configuration
// ============================================================================

/// AES cipher modes supported by the vault
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CipherMode {
    CBC = 1,
    CTR = 2,
    #[default]
    GCM = 3,
}

impl CipherMode {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => CipherMode::CBC,
            2 => CipherMode::CTR,
            3 => CipherMode::GCM,
            _ => CipherMode::GCM,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CipherMode::CBC => "CBC",
            CipherMode::CTR => "CTR",
            CipherMode::GCM => "GCM",
        }
    }

    pub fn all() -> &'static [CipherMode] {
        &[CipherMode::CBC, CipherMode::CTR, CipherMode::GCM]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub aes_mode: CipherMode,
    pub aes_key_size: u32,
    pub pbkdf2_iterations: u32,
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub default_password_length: u32,
    pub max_category_name_length: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            aes_mode: CipherMode::GCM,
            aes_key_size: 256,
            pbkdf2_iterations: 100_000,
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
            default_password_length: 16,
            max_category_name_length: 30,
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let config_path = Self::config_path();
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(config) => return config,
                    Err(_) => {}
                },
                Err(_) => {}
            }
        }
        let config = Config::default();
        config.save();
        config
    }

    pub fn save(&self) {
        let config_path = Self::config_path();
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = fs::write(config_path, content);
        }
    }

    fn config_path() -> PathBuf {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        exe_dir.join(CONFIG_FILE_NAME)
    }
}

// ============================================================================
// Cryptography
// ============================================================================

// Type aliases for CBC and CTR modes
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256Ctr = ctr::Ctr64BE<Aes256>;

pub struct VaultCrypto;

impl VaultCrypto {
    /// Derive a key from passphrase using PBKDF2
    fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
        key
    }

    /// Compute SHA256 hash of data
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// PKCS7 padding
    fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        padded
    }

    /// PKCS7 unpadding
    fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }
        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
            return Err("Invalid padding".to_string());
        }
        // Verify all padding bytes are correct
        for &byte in &data[data.len() - padding_len..] {
            if byte as usize != padding_len {
                return Err("Invalid padding".to_string());
            }
        }
        Ok(data[..data.len() - padding_len].to_vec())
    }

    /// Encrypt plaintext using configured AES mode
    /// Header format: version(1) + mode(1) + key_size(2) + iterations(4) = 8 bytes
    pub fn encrypt(plaintext: &str, passphrase: &str, config: &Config) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();

        // Generate random salt (16 bytes) and IV (16 bytes)
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        rng.fill(&mut salt);
        rng.fill(&mut iv);

        // Derive key
        let key = Self::derive_key(passphrase, &salt, config.pbkdf2_iterations);

        // Build header: version(1) + mode(1) + key_size(2) + iterations(4)
        let mut output = Vec::new();
        output.push(VAULT_VERSION);
        output.push(config.aes_mode.to_byte());
        output.extend_from_slice(&(config.aes_key_size as u16).to_be_bytes());
        output.extend_from_slice(&config.pbkdf2_iterations.to_be_bytes());

        // Salt
        output.extend_from_slice(&salt);

        match config.aes_mode {
            CipherMode::GCM => {
                // For GCM, use 12-byte nonce
                let nonce_bytes: [u8; 12] = iv[..12].try_into().unwrap();
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| format!("Cipher error: {}", e))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext.as_bytes())
                    .map_err(|e| format!("Encryption error: {}", e))?;

                // Output: header(8) + salt(16) + nonce(12) + ciphertext (includes GCM tag)
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ciphertext);
            }
            CipherMode::CTR => {
                // For CTR, append hash for integrity verification
                let plaintext_bytes = plaintext.as_bytes();
                let hash = Self::compute_hash(plaintext_bytes);
                let mut data_to_encrypt = plaintext_bytes.to_vec();
                data_to_encrypt.extend_from_slice(&hash);

                let mut ciphertext = data_to_encrypt.clone();
                let mut cipher = Aes256Ctr::new_from_slices(&key, &iv)
                    .map_err(|e| format!("Cipher error: {}", e))?;
                cipher.apply_keystream(&mut ciphertext);

                // Output: header(8) + salt(16) + iv(16) + ciphertext
                output.extend_from_slice(&iv);
                output.extend_from_slice(&ciphertext);
            }
            CipherMode::CBC => {
                // For CBC, append hash and pad
                let plaintext_bytes = plaintext.as_bytes();
                let hash = Self::compute_hash(plaintext_bytes);
                let mut data_to_encrypt = plaintext_bytes.to_vec();
                data_to_encrypt.extend_from_slice(&hash);
                let mut padded = Self::pkcs7_pad(&data_to_encrypt, 16);
                let padded_len = padded.len();

                let cipher = Aes256CbcEnc::new_from_slices(&key, &iv)
                    .map_err(|e| format!("Cipher error: {}", e))?;
                cipher.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut padded, padded_len)
                    .map_err(|_| "CBC encryption failed".to_string())?;

                // Output: header(8) + salt(16) + iv(16) + ciphertext
                output.extend_from_slice(&iv);
                output.extend_from_slice(&padded);
            }
        }

        Ok(output)
    }

    /// Decrypt data using parameters stored in the encrypted file
    pub fn decrypt(encrypted_data: &[u8], passphrase: &str) -> Result<String, String> {
        if encrypted_data.len() < 36 {
            return Err("Invalid vault file: too short".to_string());
        }

        // Parse header
        let version = encrypted_data[0];
        if version != VAULT_VERSION {
            return Err(format!("Unsupported vault version: {}", version));
        }

        // Detect old format vs new format
        // Old format: version(1) + key_size(2) + iterations(4) + reserved(1) = key_size at bytes 1-2
        // New format: version(1) + mode(1) + key_size(2) + iterations(4) = mode at byte 1
        // In old format, bytes 1-2 = 0x0100 (256), so byte 2 = 0x00
        // In new format, byte 2 is high byte of key_size (0x01 for 256)
        let is_old_format = encrypted_data[2] == 0x00 && encrypted_data[1] != 0x00;

        let (cipher_mode, iterations, salt_start) = if is_old_format {
            // Old format: version(1) + key_size(2) + iterations(4) + reserved(1) + salt(16) + nonce(12)
            let iterations = u32::from_be_bytes([
                encrypted_data[3],
                encrypted_data[4],
                encrypted_data[5],
                encrypted_data[6],
            ]);
            (CipherMode::GCM, iterations, 8)
        } else {
            // New format: version(1) + mode(1) + key_size(2) + iterations(4) + salt(16)
            let cipher_mode = CipherMode::from_byte(encrypted_data[1]);
            let iterations = u32::from_be_bytes([
                encrypted_data[4],
                encrypted_data[5],
                encrypted_data[6],
                encrypted_data[7],
            ]);
            (cipher_mode, iterations, 8)
        };

        // Extract salt
        let salt = &encrypted_data[salt_start..salt_start + 16];

        // Derive key
        let key = Self::derive_key(passphrase, salt, iterations);

        let nonce_start = salt_start + 16;

        match cipher_mode {
            CipherMode::GCM => {
                // GCM: header(8) + salt(16) + nonce(12) + ciphertext
                if encrypted_data.len() < nonce_start + 12 {
                    return Err("Invalid vault file: too short for GCM".to_string());
                }
                let nonce_bytes = &encrypted_data[nonce_start..nonce_start + 12];
                let ciphertext = &encrypted_data[nonce_start + 12..];

                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| format!("Cipher error: {}", e))?;
                let nonce = Nonce::from_slice(nonce_bytes);

                let plaintext = cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| "Decryption failed: invalid passphrase or corrupted data".to_string())?;

                String::from_utf8(plaintext).map_err(|e| format!("UTF-8 error: {}", e))
            }
            CipherMode::CTR => {
                // CTR: header(8) + salt(16) + iv(16) + ciphertext
                if encrypted_data.len() < nonce_start + 16 {
                    return Err("Invalid vault file: too short for CTR".to_string());
                }
                let iv = &encrypted_data[nonce_start..nonce_start + 16];
                let ciphertext = &encrypted_data[nonce_start + 16..];

                let mut decrypted = ciphertext.to_vec();
                let mut cipher = Aes256Ctr::new_from_slices(&key, iv)
                    .map_err(|e| format!("Cipher error: {}", e))?;
                cipher.apply_keystream(&mut decrypted);

                // Verify hash
                if decrypted.len() < 32 {
                    return Err("Invalid data: too short".to_string());
                }
                let plaintext_bytes = &decrypted[..decrypted.len() - 32];
                let stored_hash = &decrypted[decrypted.len() - 32..];
                let computed_hash = Self::compute_hash(plaintext_bytes);

                if stored_hash != computed_hash {
                    return Err("Decryption failed: invalid passphrase or corrupted data".to_string());
                }

                String::from_utf8(plaintext_bytes.to_vec())
                    .map_err(|e| format!("UTF-8 error: {}", e))
            }
            CipherMode::CBC => {
                // CBC: header(8) + salt(16) + iv(16) + ciphertext
                if encrypted_data.len() < nonce_start + 16 {
                    return Err("Invalid vault file: too short for CBC".to_string());
                }
                let iv = &encrypted_data[nonce_start..nonce_start + 16];
                let ciphertext = &encrypted_data[nonce_start + 16..];

                let cipher = Aes256CbcDec::new_from_slices(&key, iv)
                    .map_err(|e| format!("Cipher error: {}", e))?;

                let mut decrypted = ciphertext.to_vec();
                cipher.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
                    .map_err(|_| "Decryption failed".to_string())?;

                // Unpad and verify hash
                let unpadded = Self::pkcs7_unpad(&decrypted)?;
                if unpadded.len() < 32 {
                    return Err("Invalid data: too short".to_string());
                }
                let plaintext_bytes = &unpadded[..unpadded.len() - 32];
                let stored_hash = &unpadded[unpadded.len() - 32..];
                let computed_hash = Self::compute_hash(plaintext_bytes);

                if stored_hash != computed_hash {
                    return Err("Decryption failed: invalid passphrase or corrupted data".to_string());
                }

                String::from_utf8(plaintext_bytes.to_vec())
                    .map_err(|e| format!("UTF-8 error: {}", e))
            }
        }
    }

    /// Read vault header without decrypting
    pub fn read_header(data: &[u8]) -> Option<VaultProperties> {
        if data.len() < 8 {
            return None;
        }

        let version = data[0];
        if version != VAULT_VERSION {
            return None;
        }

        // Detect old format vs new format
        // Old format: bytes 1-2 = 0x0100 (256), so byte 2 = 0x00
        // New format: byte 2 is high byte of key_size (0x01 for 256)
        let is_old_format = data[2] == 0x00 && data[1] != 0x00;

        let (cipher_mode, key_size, iterations) = if is_old_format {
            // Old format: version(1) + key_size(2) + iterations(4) + reserved(1)
            let key_size = u16::from_be_bytes([data[1], data[2]]) as u32;
            let iterations = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
            (CipherMode::GCM, key_size, iterations)
        } else {
            // New format: version(1) + mode(1) + key_size(2) + iterations(4)
            let cipher_mode = CipherMode::from_byte(data[1]);
            let key_size = u16::from_be_bytes([data[2], data[3]]) as u32;
            let iterations = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            (cipher_mode, key_size, iterations)
        };

        Some(VaultProperties {
            version,
            cipher_mode,
            key_size,
            iterations,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VaultProperties {
    pub version: u8,
    pub cipher_mode: CipherMode,
    pub key_size: u32,
    pub iterations: u32,
}

// ============================================================================
// Password Generator
// ============================================================================
pub struct PasswordGenerator;

impl PasswordGenerator {
    pub fn generate(
        length: usize,
        use_upper: bool,
        use_lower: bool,
        use_digits: bool,
        use_special: bool,
        exclude_ambiguous: bool,
    ) -> String {
        let mut rng = rand::thread_rng();
        let mut chars = String::new();

        let uppercase = if exclude_ambiguous {
            "ABCDEFGHJKLMNPQRSTUVWXYZ" // Excluding O and I
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        };

        let lowercase = if exclude_ambiguous {
            "abcdefghjkmnpqrstuvwxyz" // Excluding l and o
        } else {
            "abcdefghijklmnopqrstuvwxyz"
        };

        let digits = if exclude_ambiguous {
            "23456789" // Excluding 0 and 1
        } else {
            "0123456789"
        };

        if use_upper {
            chars.push_str(uppercase);
        }
        if use_lower {
            chars.push_str(lowercase);
        }
        if use_digits {
            chars.push_str(digits);
        }
        if use_special {
            chars.push_str(SPECIAL_CHARS);
        }

        if chars.is_empty() {
            chars = format!("{}{}", uppercase, lowercase);
        }

        let chars: Vec<char> = chars.chars().collect();

        // Ensure at least one character from each selected category
        let mut password: Vec<char> = Vec::with_capacity(length);

        if use_upper && !uppercase.is_empty() {
            let idx = rng.gen_range(0..uppercase.len());
            password.push(uppercase.chars().nth(idx).unwrap());
        }
        if use_lower && !lowercase.is_empty() {
            let idx = rng.gen_range(0..lowercase.len());
            password.push(lowercase.chars().nth(idx).unwrap());
        }
        if use_digits && !digits.is_empty() {
            let idx = rng.gen_range(0..digits.len());
            password.push(digits.chars().nth(idx).unwrap());
        }
        if use_special {
            let idx = rng.gen_range(0..SPECIAL_CHARS.len());
            password.push(SPECIAL_CHARS.chars().nth(idx).unwrap());
        }

        // Fill the rest
        while password.len() < length {
            let idx = rng.gen_range(0..chars.len());
            password.push(chars[idx]);
        }

        // Shuffle
        for i in (1..password.len()).rev() {
            let j = rng.gen_range(0..=i);
            password.swap(i, j);
        }

        password.into_iter().collect()
    }

    pub fn calculate_strength(password: &str) -> (u32, &'static str) {
        if password.is_empty() {
            return (0, "Empty");
        }

        let mut score: u32 = 0;
        let length = password.len();

        // Length score
        if length >= 8 {
            score += 20;
        }
        if length >= 12 {
            score += 10;
        }
        if length >= 16 {
            score += 10;
        }

        // Character variety
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

        if has_lower {
            score += 15;
        }
        if has_upper {
            score += 15;
        }
        if has_digit {
            score += 15;
        }
        if has_special {
            score += 15;
        }

        let score = score.min(100);
        let desc = if score < 30 {
            "Very Weak"
        } else if score < 50 {
            "Weak"
        } else if score < 70 {
            "Fair"
        } else if score < 90 {
            "Strong"
        } else {
            "Very Strong"
        };

        (score, desc)
    }
}

// ============================================================================
// Vault Data Structures
// ============================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub created: String,
    pub modified: String,
}

impl Entry {
    pub fn new() -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub created: String,
    pub modified: String,
    pub version: String,
}

impl Default for VaultMetadata {
    fn default() -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            created: now.clone(),
            modified: now,
            version: "1.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub categories: HashMap<String, Vec<Entry>>,
    pub metadata: VaultMetadata,
}

impl VaultData {
    pub fn new() -> Self {
        let mut vault = Self::default();
        vault.categories.insert("General".to_string(), Vec::new());
        vault
    }

    pub fn add_category(&mut self, name: &str) -> bool {
        if !self.categories.contains_key(name) {
            self.categories.insert(name.to_string(), Vec::new());
            self.update_modified();
            true
        } else {
            false
        }
    }

    pub fn rename_category(&mut self, old_name: &str, new_name: &str) -> bool {
        if self.categories.contains_key(old_name) && !self.categories.contains_key(new_name) {
            if let Some(entries) = self.categories.remove(old_name) {
                self.categories.insert(new_name.to_string(), entries);
                self.update_modified();
                return true;
            }
        }
        false
    }

    pub fn delete_category(&mut self, name: &str) -> bool {
        if self.categories.remove(name).is_some() {
            self.update_modified();
            true
        } else {
            false
        }
    }

    pub fn add_entry(&mut self, category: &str, mut entry: Entry) -> bool {
        if let Some(entries) = self.categories.get_mut(category) {
            let now = Utc::now().to_rfc3339();
            entry.created = now.clone();
            entry.modified = now;
            entries.push(entry);
            self.update_modified();
            true
        } else {
            false
        }
    }

    pub fn update_entry(&mut self, category: &str, index: usize, mut entry: Entry) -> bool {
        if let Some(entries) = self.categories.get_mut(category) {
            if index < entries.len() {
                entry.created = entries[index].created.clone();
                entry.modified = Utc::now().to_rfc3339();
                entries[index] = entry;
                self.update_modified();
                return true;
            }
        }
        false
    }

    pub fn delete_entry(&mut self, category: &str, index: usize) -> bool {
        if let Some(entries) = self.categories.get_mut(category) {
            if index < entries.len() {
                entries.remove(index);
                self.update_modified();
                return true;
            }
        }
        false
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }

    fn update_modified(&mut self) {
        self.metadata.modified = Utc::now().to_rfc3339();
    }

    pub fn total_entries(&self) -> usize {
        self.categories.values().map(|v| v.len()).sum()
    }
}

// ============================================================================
// Application State
// ============================================================================
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Startup,
    Main,
    Locked,
    VaultDialog { mode: VaultDialogMode },
    EntryDialog { mode: EntryDialogMode },
    PasswordGenerator,
    ConfigDialog,
    VaultProperties,
    ConfirmDialog { title: String, message: String, action: ConfirmAction },
    CategoryInput { mode: CategoryInputMode },
}

#[derive(Debug, Clone, PartialEq)]
pub enum VaultDialogMode {
    Create,
    Open,
    Unlock,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EntryDialogMode {
    Add,
    Edit { index: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfirmAction {
    DeleteEntry { index: usize },
    DeleteCategory { name: String },
    SaveBeforeLock,
    SaveBeforeClose,
    SaveBeforeNew,
    SaveBeforeOpen,
    SaveBeforeCloseVault,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CategoryInputMode {
    Add,
    Rename { old_name: String },
}

#[derive(Debug, Clone)]
pub enum Message {
    // Navigation
    GoToScreen(Screen),
    CloseDialog,

    // Vault operations
    NewVault,
    OpenVault,
    CloseVault,
    SaveVault,
    LockVault,
    UnlockVault,
    VaultSaved(Result<(), String>),
    VaultLoaded(Result<(VaultData, VaultProperties), String>),

    // File dialog
    SelectVaultFile,
    VaultFileSelected(Option<PathBuf>),

    // Vault dialog inputs
    VaultPathChanged(String),
    PassphraseChanged(String),
    ConfirmPassphraseChanged(String),
    TogglePassphraseVisibility,

    // Category operations
    AddCategory,
    RenameCategory(String),
    DeleteCategory(String),
    SelectCategory(String),
    CategoryNameChanged(String),
    ConfirmCategoryAction,

    // Entry operations
    AddEntry,
    EditEntry(usize),
    DeleteEntry(usize),
    TogglePasswordVisibility(usize),

    // Entry dialog inputs
    EntryNameChanged(String),
    EntryUsernameChanged(String),
    EntryPasswordChanged(String),
    EntryUrlChanged(String),
    EntryNotesChanged(String),
    SaveEntry,
    GenerateEntryPassword,
    ToggleEntryPasswordVisibility,

    // Password generator
    OpenPasswordGenerator,
    PasswordLengthChanged(String),
    ToggleUppercase(bool),
    ToggleLowercase(bool),
    ToggleDigits(bool),
    ToggleSpecial(bool),
    ToggleExcludeAmbiguous(bool),
    RegeneratePassword,
    UseGeneratedPassword,

    // Clipboard
    CopyPassword(usize),
    CopyUsername(usize),
    CopyUrl(usize),
    ClearClipboard,

    // Config
    OpenConfig,
    ConfigCipherModeChanged(CipherMode),
    ConfigIterationsChanged(String),
    ConfigAutoLockChanged(String),
    ConfigClipboardClearChanged(String),
    ConfigPasswordLengthChanged(String),
    ConfigMaxCategoryLengthChanged(String),
    SaveConfig,
    ResetConfigDefaults,

    // Search
    SearchChanged(String),

    // Confirm dialog
    ConfirmYes,
    ConfirmNo,

    // Timer
    Tick(Instant),

    // Application
    CloseApp,
    ExitApp,
    WindowCloseRequested(window::Id),

    // Keyboard navigation
    FocusNext,
    FocusPrevious,
}

pub struct RustPw {
    // Vault state
    vault_data: Option<VaultData>,
    vault_path: Option<PathBuf>,
    passphrase: String,
    vault_properties: Option<VaultProperties>,
    modified: bool,

    // UI state
    screen: Screen,
    previous_screen: Option<Screen>,
    selected_category: Option<String>,
    search_text: String,
    password_visible_rows: HashSet<usize>,

    // Vault dialog state
    vault_dialog_path: String,
    vault_dialog_passphrase: String,
    vault_dialog_confirm: String,
    vault_dialog_passphrase_visible: bool,
    vault_dialog_error: Option<String>,

    // Entry dialog state
    entry_dialog: Entry,
    entry_dialog_password_visible: bool,

    // Password generator state
    pw_gen_length: u32,
    pw_gen_upper: bool,
    pw_gen_lower: bool,
    pw_gen_digits: bool,
    pw_gen_special: bool,
    pw_gen_exclude_ambiguous: bool,
    pw_gen_password: String,
    pw_gen_for_entry: bool,

    // Category input state
    category_input: String,

    // Config state
    config: Config,
    config_edit: Config,

    // Timer state
    last_activity: Instant,
    clipboard_clear_time: Option<Instant>,

    // Status
    status_message: String,
}

impl Default for RustPw {
    fn default() -> Self {
        let config = Config::load();
        let pw_len = config.default_password_length;

        Self {
            vault_data: None,
            vault_path: None,
            passphrase: String::new(),
            vault_properties: None,
            modified: false,

            screen: Screen::Startup,
            previous_screen: None,
            selected_category: None,
            search_text: String::new(),
            password_visible_rows: HashSet::new(),

            vault_dialog_path: String::new(),
            vault_dialog_passphrase: String::new(),
            vault_dialog_confirm: String::new(),
            vault_dialog_passphrase_visible: false,
            vault_dialog_error: None,

            entry_dialog: Entry::new(),
            entry_dialog_password_visible: false,

            pw_gen_length: pw_len,
            pw_gen_upper: true,
            pw_gen_lower: true,
            pw_gen_digits: true,
            pw_gen_special: true,
            pw_gen_exclude_ambiguous: false,
            pw_gen_password: String::new(),
            pw_gen_for_entry: false,

            category_input: String::new(),

            config: config.clone(),
            config_edit: config,

            last_activity: Instant::now(),
            clipboard_clear_time: None,

            status_message: "Ready".to_string(),
        }
    }
}

impl RustPw {
    fn new() -> (Self, Task<Message>) {
        (Self::default(), Task::none())
    }

    fn title(&self) -> String {
        if let Some(path) = &self.vault_path {
            let name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
            format!("{} - {}", APP_NAME, name)
        } else {
            APP_NAME.to_string()
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        // Reset activity timer on any user interaction
        self.last_activity = Instant::now();

        match message {
            // Navigation
            Message::GoToScreen(screen) => {
                self.previous_screen = Some(self.screen.clone());
                self.screen = screen;
            }
            Message::CloseDialog => {
                if let Some(prev) = self.previous_screen.take() {
                    self.screen = prev;
                } else {
                    self.screen = Screen::Main;
                }
                self.vault_dialog_error = None;
            }

            // Vault operations
            Message::NewVault => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before creating a new vault?".to_string(),
                        action: ConfirmAction::SaveBeforeNew,
                    };
                } else {
                    self.reset_vault_dialog();
                    self.screen = Screen::VaultDialog {
                        mode: VaultDialogMode::Create,
                    };
                    return text_input::focus(id_vault_path());
                }
            }
            Message::OpenVault => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before opening another vault?".to_string(),
                        action: ConfirmAction::SaveBeforeOpen,
                    };
                } else {
                    self.reset_vault_dialog();
                    self.screen = Screen::VaultDialog {
                        mode: VaultDialogMode::Open,
                    };
                    return text_input::focus(id_vault_path());
                }
            }
            Message::CloseVault => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before closing the vault?".to_string(),
                        action: ConfirmAction::SaveBeforeCloseVault,
                    };
                } else {
                    self.close_vault();
                }
            }
            Message::SaveVault => {
                return self.save_vault();
            }
            Message::LockVault => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before locking?".to_string(),
                        action: ConfirmAction::SaveBeforeLock,
                    };
                } else {
                    self.lock_vault();
                }
            }
            Message::UnlockVault => {
                self.reset_vault_dialog();
                if let Some(path) = &self.vault_path {
                    self.vault_dialog_path = path.to_string_lossy().to_string();
                }
                self.screen = Screen::VaultDialog {
                    mode: VaultDialogMode::Unlock,
                };
                return text_input::focus(id_passphrase());
            }
            Message::VaultSaved(result) => {
                match result {
                    Ok(()) => {
                        self.modified = false;
                        self.status_message = "Vault saved".to_string();
                    }
                    Err(e) => {
                        self.status_message = format!("Error saving vault: {}", e);
                    }
                }
            }
            Message::VaultLoaded(result) => {
                match result {
                    Ok((data, props)) => {
                        self.vault_data = Some(data);
                        self.vault_properties = Some(props);
                        self.passphrase = self.vault_dialog_passphrase.clone();
                        self.modified = false;
                        self.password_visible_rows.clear();

                        // Select first category
                        if let Some(ref data) = self.vault_data {
                            self.selected_category = data.categories.keys().next().cloned();
                        }

                        self.screen = Screen::Main;
                        self.status_message = "Vault opened".to_string();
                        self.reset_vault_dialog();
                    }
                    Err(e) => {
                        self.vault_dialog_error = Some(e);
                    }
                }
            }

            // File dialog
            Message::SelectVaultFile => {
                let mode = if let Screen::VaultDialog { mode } = &self.screen {
                    mode.clone()
                } else {
                    VaultDialogMode::Open
                };

                return Task::perform(
                    async move {
                        let dialog = rfd::AsyncFileDialog::new()
                            .add_filter("RustPw Vault", &[VAULT_FILE_EXTENSION])
                            .add_filter("All Files", &["*"]);

                        match mode {
                            VaultDialogMode::Create => {
                                dialog
                                    .set_file_name("vault.rustpw")
                                    .save_file()
                                    .await
                                    .map(|h| h.path().to_path_buf())
                            }
                            _ => dialog.pick_file().await.map(|h| h.path().to_path_buf()),
                        }
                    },
                    Message::VaultFileSelected,
                );
            }
            Message::VaultFileSelected(path) => {
                if let Some(p) = path {
                    self.vault_dialog_path = p.to_string_lossy().to_string();
                }
            }

            // Vault dialog inputs
            Message::VaultPathChanged(s) => {
                self.vault_dialog_path = s;
            }
            Message::PassphraseChanged(s) => {
                self.vault_dialog_passphrase = s;
            }
            Message::ConfirmPassphraseChanged(s) => {
                self.vault_dialog_confirm = s;
            }
            Message::TogglePassphraseVisibility => {
                self.vault_dialog_passphrase_visible = !self.vault_dialog_passphrase_visible;
            }

            // Handle vault dialog submission based on mode
            Message::ConfirmYes => {
                if let Screen::VaultDialog { mode } = &self.screen {
                    match mode {
                        VaultDialogMode::Create => {
                            return self.create_vault();
                        }
                        VaultDialogMode::Open | VaultDialogMode::Unlock => {
                            return self.open_vault();
                        }
                    }
                } else if let Screen::ConfirmDialog { action, .. } = &self.screen {
                    match action.clone() {
                        ConfirmAction::DeleteEntry { index } => {
                            self.delete_entry(index);
                            self.screen = Screen::Main;
                            // Auto-save vault after entry deletion
                            return self.save_vault();
                        }
                        ConfirmAction::DeleteCategory { name } => {
                            self.delete_category(&name);
                            self.screen = Screen::Main;
                            // Auto-save vault after category deletion
                            return self.save_vault();
                        }
                        ConfirmAction::SaveBeforeLock => {
                            let cmd = self.save_vault();
                            self.lock_vault();
                            return cmd;
                        }
                        ConfirmAction::SaveBeforeClose => {
                            let cmd = self.save_vault();
                            return Task::batch([cmd, Task::perform(async {}, |_| Message::ExitApp)]);
                        }
                        ConfirmAction::SaveBeforeNew => {
                            let cmd = self.save_vault();
                            self.reset_vault_dialog();
                            self.screen = Screen::VaultDialog {
                                mode: VaultDialogMode::Create,
                            };
                            return Task::batch([cmd, text_input::focus(id_vault_path())]);
                        }
                        ConfirmAction::SaveBeforeOpen => {
                            let cmd = self.save_vault();
                            self.reset_vault_dialog();
                            self.screen = Screen::VaultDialog {
                                mode: VaultDialogMode::Open,
                            };
                            return Task::batch([cmd, text_input::focus(id_vault_path())]);
                        }
                        ConfirmAction::SaveBeforeCloseVault => {
                            let cmd = self.save_vault();
                            self.close_vault();
                            return cmd;
                        }
                    }
                } else if let Screen::CategoryInput { mode } = &self.screen {
                    match mode {
                        CategoryInputMode::Add => {
                            self.add_category();
                        }
                        CategoryInputMode::Rename { old_name } => {
                            self.rename_category_confirm(old_name.clone());
                        }
                    }
                    // Auto-save vault after category changes
                    return self.save_vault();
                }
            }
            Message::ConfirmNo => {
                if let Screen::ConfirmDialog { action, .. } = &self.screen {
                    match action {
                        ConfirmAction::SaveBeforeLock => {
                            self.lock_vault();
                        }
                        ConfirmAction::SaveBeforeClose => {
                            return Task::perform(async {}, |_| Message::ExitApp);
                        }
                        ConfirmAction::SaveBeforeNew => {
                            self.reset_vault_dialog();
                            self.screen = Screen::VaultDialog {
                                mode: VaultDialogMode::Create,
                            };
                            return text_input::focus(id_vault_path());
                        }
                        ConfirmAction::SaveBeforeOpen => {
                            self.reset_vault_dialog();
                            self.screen = Screen::VaultDialog {
                                mode: VaultDialogMode::Open,
                            };
                            return text_input::focus(id_vault_path());
                        }
                        ConfirmAction::SaveBeforeCloseVault => {
                            self.close_vault();
                        }
                        _ => {
                            self.screen = Screen::Main;
                        }
                    }
                } else {
                    self.screen = Screen::Main;
                }
            }

            // Category operations
            Message::AddCategory => {
                self.category_input.clear();
                self.screen = Screen::CategoryInput {
                    mode: CategoryInputMode::Add,
                };
                return text_input::focus(id_category_name());
            }
            Message::RenameCategory(name) => {
                self.category_input = name.clone();
                self.screen = Screen::CategoryInput {
                    mode: CategoryInputMode::Rename { old_name: name },
                };
                return text_input::focus(id_category_name());
            }
            Message::DeleteCategory(name) => {
                self.screen = Screen::ConfirmDialog {
                    title: "Delete Category".to_string(),
                    message: format!("Delete category '{}' and all its entries?", name),
                    action: ConfirmAction::DeleteCategory { name },
                };
            }
            Message::SelectCategory(name) => {
                self.selected_category = Some(name);
                self.password_visible_rows.clear();
            }
            Message::CategoryNameChanged(s) => {
                self.category_input = s;
            }
            Message::ConfirmCategoryAction => {
                if let Screen::CategoryInput { mode } = &self.screen {
                    match mode {
                        CategoryInputMode::Add => {
                            self.add_category();
                        }
                        CategoryInputMode::Rename { old_name } => {
                            self.rename_category_confirm(old_name.clone());
                        }
                    }
                    // Auto-save vault after category changes
                    return self.save_vault();
                }
            }

            // Entry operations
            Message::AddEntry => {
                self.entry_dialog = Entry::new();
                self.entry_dialog_password_visible = false;
                self.screen = Screen::EntryDialog {
                    mode: EntryDialogMode::Add,
                };
                return text_input::focus(id_entry_name());
            }
            Message::EditEntry(index) => {
                if let Some(ref data) = self.vault_data {
                    if let Some(category) = &self.selected_category {
                        if let Some(entries) = data.categories.get(category) {
                            if let Some(entry) = entries.get(index) {
                                self.entry_dialog = entry.clone();
                                self.entry_dialog_password_visible = false;
                                self.screen = Screen::EntryDialog {
                                    mode: EntryDialogMode::Edit { index },
                                };
                                return text_input::focus(id_entry_name());
                            }
                        }
                    }
                }
            }
            Message::DeleteEntry(index) => {
                self.screen = Screen::ConfirmDialog {
                    title: "Delete Entry".to_string(),
                    message: "Are you sure you want to delete this entry?".to_string(),
                    action: ConfirmAction::DeleteEntry { index },
                };
            }
            Message::TogglePasswordVisibility(index) => {
                if self.password_visible_rows.contains(&index) {
                    self.password_visible_rows.remove(&index);
                } else {
                    self.password_visible_rows.insert(index);
                }
            }

            // Entry dialog inputs
            Message::EntryNameChanged(s) => self.entry_dialog.name = s,
            Message::EntryUsernameChanged(s) => self.entry_dialog.username = s,
            Message::EntryPasswordChanged(s) => self.entry_dialog.password = s,
            Message::EntryUrlChanged(s) => self.entry_dialog.url = s,
            Message::EntryNotesChanged(s) => self.entry_dialog.notes = s,
            Message::SaveEntry => {
                if let Screen::EntryDialog { mode } = &self.screen {
                    match mode {
                        EntryDialogMode::Add => {
                            self.add_entry();
                        }
                        EntryDialogMode::Edit { index } => {
                            self.update_entry(*index);
                        }
                    }
                    // Auto-save vault after entry changes
                    return self.save_vault();
                }
            }
            Message::GenerateEntryPassword => {
                self.pw_gen_for_entry = true;
                self.regenerate_password();
                self.previous_screen = Some(self.screen.clone());
                self.screen = Screen::PasswordGenerator;
            }
            Message::ToggleEntryPasswordVisibility => {
                self.entry_dialog_password_visible = !self.entry_dialog_password_visible;
            }

            // Password generator
            Message::OpenPasswordGenerator => {
                self.pw_gen_for_entry = false;
                self.regenerate_password();
                self.previous_screen = Some(self.screen.clone());
                self.screen = Screen::PasswordGenerator;
            }
            Message::PasswordLengthChanged(s) => {
                if let Ok(len) = s.parse::<u32>() {
                    if len >= 4 && len <= 128 {
                        self.pw_gen_length = len;
                        self.regenerate_password();
                    }
                }
            }
            Message::ToggleUppercase(v) => {
                self.pw_gen_upper = v;
                self.regenerate_password();
            }
            Message::ToggleLowercase(v) => {
                self.pw_gen_lower = v;
                self.regenerate_password();
            }
            Message::ToggleDigits(v) => {
                self.pw_gen_digits = v;
                self.regenerate_password();
            }
            Message::ToggleSpecial(v) => {
                self.pw_gen_special = v;
                self.regenerate_password();
            }
            Message::ToggleExcludeAmbiguous(v) => {
                self.pw_gen_exclude_ambiguous = v;
                self.regenerate_password();
            }
            Message::RegeneratePassword => {
                self.regenerate_password();
            }
            Message::UseGeneratedPassword => {
                if self.pw_gen_for_entry {
                    self.entry_dialog.password = self.pw_gen_password.clone();
                }
                self.screen = self.previous_screen.take().unwrap_or(Screen::Main);
            }

            // Clipboard
            Message::CopyPassword(index) => {
                let text_to_copy = self.vault_data.as_ref()
                    .and_then(|data| self.selected_category.as_ref()
                        .and_then(|cat| data.categories.get(cat))
                        .and_then(|entries| entries.get(index))
                        .map(|entry| entry.password.clone()));
                if let Some(text) = text_to_copy {
                    self.copy_to_clipboard(&text);
                }
            }
            Message::CopyUsername(index) => {
                let text_to_copy = self.vault_data.as_ref()
                    .and_then(|data| self.selected_category.as_ref()
                        .and_then(|cat| data.categories.get(cat))
                        .and_then(|entries| entries.get(index))
                        .map(|entry| entry.username.clone()));
                if let Some(text) = text_to_copy {
                    self.copy_to_clipboard(&text);
                }
            }
            Message::CopyUrl(index) => {
                let text_to_copy = self.vault_data.as_ref()
                    .and_then(|data| self.selected_category.as_ref()
                        .and_then(|cat| data.categories.get(cat))
                        .and_then(|entries| entries.get(index))
                        .map(|entry| entry.url.clone()));
                if let Some(text) = text_to_copy {
                    self.copy_to_clipboard(&text);
                }
            }
            Message::ClearClipboard => {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    let _ = clipboard.clear();
                }
                self.clipboard_clear_time = None;
                self.status_message = "Clipboard cleared".to_string();
            }

            // Config
            Message::OpenConfig => {
                self.config_edit = self.config.clone();
                self.previous_screen = Some(self.screen.clone());
                self.screen = Screen::ConfigDialog;
            }
            Message::ConfigCipherModeChanged(mode) => {
                self.config_edit.aes_mode = mode;
            }
            Message::ConfigIterationsChanged(s) => {
                if let Ok(v) = s.parse() {
                    self.config_edit.pbkdf2_iterations = v;
                }
            }
            Message::ConfigAutoLockChanged(s) => {
                if let Ok(v) = s.parse() {
                    self.config_edit.auto_lock_minutes = v;
                }
            }
            Message::ConfigClipboardClearChanged(s) => {
                if let Ok(v) = s.parse() {
                    self.config_edit.clipboard_clear_seconds = v;
                }
            }
            Message::ConfigPasswordLengthChanged(s) => {
                if let Ok(v) = s.parse() {
                    self.config_edit.default_password_length = v;
                }
            }
            Message::ConfigMaxCategoryLengthChanged(s) => {
                if let Ok(v) = s.parse() {
                    self.config_edit.max_category_name_length = v;
                }
            }
            Message::SaveConfig => {
                self.config = self.config_edit.clone();
                self.config.save();
                self.pw_gen_length = self.config.default_password_length;
                self.status_message = "Configuration saved".to_string();
                self.screen = self.previous_screen.take().unwrap_or(Screen::Main);
            }
            Message::ResetConfigDefaults => {
                self.config_edit = Config::default();
            }

            // Search
            Message::SearchChanged(s) => {
                self.search_text = s;
            }

            // Timer
            Message::Tick(now) => {
                // Check for auto-lock
                if self.vault_data.is_some() && self.screen == Screen::Main {
                    let elapsed = now.duration_since(self.last_activity);
                    if elapsed >= Duration::from_secs(self.config.auto_lock_minutes as u64 * 60) {
                        if self.modified {
                            let _ = self.save_vault();
                        }
                        self.lock_vault();
                    }
                }

                // Check for clipboard clear
                if let Some(clear_time) = self.clipboard_clear_time {
                    if now >= clear_time {
                        return Task::perform(async {}, |_| Message::ClearClipboard);
                    }
                }
            }

            // Application
            Message::CloseApp => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before closing?".to_string(),
                        action: ConfirmAction::SaveBeforeClose,
                    };
                } else {
                    return Task::perform(async {}, |_| Message::ExitApp);
                }
            }
            Message::ExitApp => {
                return window::get_latest().and_then(window::close);
            }
            Message::WindowCloseRequested(id) => {
                if self.modified {
                    self.screen = Screen::ConfirmDialog {
                        title: "Unsaved Changes".to_string(),
                        message: "Save changes before closing?".to_string(),
                        action: ConfirmAction::SaveBeforeClose,
                    };
                } else {
                    return window::close(id);
                }
            }

            // Keyboard navigation
            Message::FocusNext => {
                return widget::focus_next();
            }
            Message::FocusPrevious => {
                return widget::focus_previous();
            }
        }

        Task::none()
    }

    fn view(&self) -> Element<Message> {
        match &self.screen {
            Screen::Startup => self.view_startup(),
            Screen::Main => self.view_main(),
            Screen::Locked => self.view_locked(),
            Screen::VaultDialog { mode } => self.view_vault_dialog(mode),
            Screen::EntryDialog { mode } => self.view_entry_dialog(mode),
            Screen::PasswordGenerator => self.view_password_generator(),
            Screen::ConfigDialog => self.view_config_dialog(),
            Screen::VaultProperties => self.view_vault_properties(),
            Screen::ConfirmDialog { title, message, .. } => self.view_confirm_dialog(title, message),
            Screen::CategoryInput { mode } => self.view_category_input(mode),
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            time::every(Duration::from_secs(1)).map(Message::Tick),
            window::close_requests().map(Message::WindowCloseRequested),
            keyboard::on_key_press(|key, modifiers| {
                if key == keyboard::Key::Named(keyboard::key::Named::Tab) {
                    if modifiers.shift() {
                        Some(Message::FocusPrevious)
                    } else {
                        Some(Message::FocusNext)
                    }
                } else {
                    None
                }
            }),
        ])
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

// ============================================================================
// Helper Methods
// ============================================================================
impl RustPw {
    fn reset_vault_dialog(&mut self) {
        self.vault_dialog_path.clear();
        self.vault_dialog_passphrase.clear();
        self.vault_dialog_confirm.clear();
        self.vault_dialog_passphrase_visible = false;
        self.vault_dialog_error = None;
    }

    fn create_vault(&mut self) -> Task<Message> {
        // Validation
        if self.vault_dialog_path.is_empty() {
            self.vault_dialog_error = Some("Please select a vault file.".to_string());
            return Task::none();
        }
        if self.vault_dialog_passphrase.is_empty() {
            self.vault_dialog_error = Some("Please enter a passphrase.".to_string());
            return Task::none();
        }
        if self.vault_dialog_passphrase != self.vault_dialog_confirm {
            self.vault_dialog_error = Some("Passphrases do not match.".to_string());
            return Task::none();
        }
        if self.vault_dialog_passphrase.len() < 8 {
            self.vault_dialog_error = Some("Passphrase must be at least 8 characters.".to_string());
            return Task::none();
        }

        // Create new vault
        let path = PathBuf::from(&self.vault_dialog_path);
        let passphrase = self.vault_dialog_passphrase.clone();
        let config = self.config.clone();

        self.vault_data = Some(VaultData::new());
        self.vault_path = Some(path.clone());
        self.passphrase = passphrase.clone();
        self.vault_properties = Some(VaultProperties {
            version: VAULT_VERSION,
            cipher_mode: config.aes_mode,
            key_size: config.aes_key_size,
            iterations: config.pbkdf2_iterations,
        });
        self.selected_category = Some("General".to_string());
        self.modified = false;
        self.screen = Screen::Main;
        self.status_message = "New vault created".to_string();

        // Save immediately
        self.save_vault()
    }

    fn open_vault(&mut self) -> Task<Message> {
        if self.vault_dialog_path.is_empty() {
            self.vault_dialog_error = Some("Please select a vault file.".to_string());
            return Task::none();
        }
        if self.vault_dialog_passphrase.is_empty() {
            self.vault_dialog_error = Some("Please enter the passphrase.".to_string());
            return Task::none();
        }

        let path = PathBuf::from(&self.vault_dialog_path);
        let passphrase = self.vault_dialog_passphrase.clone();

        self.vault_path = Some(path.clone());

        Task::perform(
            async move {
                let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

                let props = VaultCrypto::read_header(&data)
                    .ok_or_else(|| "Invalid vault file format".to_string())?;

                let json = VaultCrypto::decrypt(&data, &passphrase)?;

                let vault_data =
                    VaultData::from_json(&json).map_err(|e| format!("Failed to parse vault: {}", e))?;

                Ok((vault_data, props))
            },
            Message::VaultLoaded,
        )
    }

    fn save_vault(&self) -> Task<Message> {
        let Some(ref vault_data) = self.vault_data else {
            return Task::none();
        };
        let Some(ref path) = self.vault_path else {
            return Task::none();
        };

        let json = match vault_data.to_json() {
            Ok(j) => j,
            Err(e) => return Task::perform(async move { Err(e) }, Message::VaultSaved),
        };

        let passphrase = self.passphrase.clone();
        let config = self.config.clone();
        let path = path.clone();

        Task::perform(
            async move {
                let encrypted = VaultCrypto::encrypt(&json, &passphrase, &config)?;
                fs::write(&path, encrypted).map_err(|e| format!("Failed to write file: {}", e))?;
                Ok(())
            },
            Message::VaultSaved,
        )
    }

    fn lock_vault(&mut self) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.password_visible_rows.clear();
        self.screen = Screen::Locked;
        self.status_message = "Vault locked".to_string();
    }

    fn close_vault(&mut self) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.vault_data = None;
        self.vault_path = None;
        self.vault_properties = None;
        self.selected_category = None;
        self.password_visible_rows.clear();
        self.modified = false;
        self.screen = Screen::Startup;
        self.status_message = "Vault closed".to_string();
    }

    fn add_category(&mut self) {
        let name = self.category_input.trim().to_string();
        if name.is_empty() {
            return;
        }
        if name.len() > self.config.max_category_name_length as usize {
            self.status_message = format!(
                "Category name too long (max {} chars)",
                self.config.max_category_name_length
            );
            return;
        }

        if let Some(ref mut data) = self.vault_data {
            if data.add_category(&name) {
                self.selected_category = Some(name.clone());
                self.modified = true;
                self.status_message = format!("Category '{}' added", name);
            } else {
                self.status_message = "Category already exists".to_string();
            }
        }

        self.category_input.clear();
        self.screen = Screen::Main;
    }

    fn rename_category_confirm(&mut self, old_name: String) {
        let new_name = self.category_input.trim().to_string();
        if new_name.is_empty() || new_name == old_name {
            self.screen = Screen::Main;
            return;
        }
        if new_name.len() > self.config.max_category_name_length as usize {
            self.status_message = format!(
                "Category name too long (max {} chars)",
                self.config.max_category_name_length
            );
            return;
        }

        if let Some(ref mut data) = self.vault_data {
            if data.rename_category(&old_name, &new_name) {
                if self.selected_category.as_ref() == Some(&old_name) {
                    self.selected_category = Some(new_name.clone());
                }
                self.modified = true;
                self.status_message = format!("Category renamed to '{}'", new_name);
            } else {
                self.status_message = "Category name already exists".to_string();
            }
        }

        self.category_input.clear();
        self.screen = Screen::Main;
    }

    fn delete_category(&mut self, name: &str) {
        if let Some(ref mut data) = self.vault_data {
            if data.delete_category(name) {
                if self.selected_category.as_ref() == Some(&name.to_string()) {
                    self.selected_category = data.categories.keys().next().cloned();
                }
                self.modified = true;
                self.status_message = format!("Category '{}' deleted", name);
            }
        }
    }

    fn add_entry(&mut self) {
        if let Some(category) = &self.selected_category.clone() {
            if let Some(ref mut data) = self.vault_data {
                if data.add_entry(category, self.entry_dialog.clone()) {
                    self.modified = true;
                    self.status_message = "Entry added".to_string();
                }
            }
        }
        self.screen = Screen::Main;
    }

    fn update_entry(&mut self, index: usize) {
        if let Some(category) = &self.selected_category.clone() {
            if let Some(ref mut data) = self.vault_data {
                if data.update_entry(category, index, self.entry_dialog.clone()) {
                    self.modified = true;
                    self.status_message = "Entry updated".to_string();
                }
            }
        }
        self.screen = Screen::Main;
    }

    fn delete_entry(&mut self, index: usize) {
        if let Some(category) = &self.selected_category.clone() {
            if let Some(ref mut data) = self.vault_data {
                if data.delete_entry(category, index) {
                    self.password_visible_rows.remove(&index);
                    self.modified = true;
                    self.status_message = "Entry deleted".to_string();
                }
            }
        }
    }

    fn regenerate_password(&mut self) {
        self.pw_gen_password = PasswordGenerator::generate(
            self.pw_gen_length as usize,
            self.pw_gen_upper,
            self.pw_gen_lower,
            self.pw_gen_digits,
            self.pw_gen_special,
            self.pw_gen_exclude_ambiguous,
        );
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            if clipboard.set_text(text.to_string()).is_ok() {
                self.clipboard_clear_time = Some(
                    Instant::now() + Duration::from_secs(self.config.clipboard_clear_seconds as u64),
                );
                self.status_message = format!(
                    "Copied to clipboard (will clear in {} seconds)",
                    self.config.clipboard_clear_seconds
                );
            }
        }
    }

    fn get_filtered_entries(&self) -> Vec<(usize, &Entry)> {
        let Some(ref data) = self.vault_data else {
            return Vec::new();
        };
        let Some(ref category) = self.selected_category else {
            return Vec::new();
        };
        let Some(entries) = data.categories.get(category) else {
            return Vec::new();
        };

        let search = self.search_text.to_lowercase();
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                if search.is_empty() {
                    return true;
                }
                entry.name.to_lowercase().contains(&search)
                    || entry.username.to_lowercase().contains(&search)
                    || entry.url.to_lowercase().contains(&search)
                    || entry.notes.to_lowercase().contains(&search)
            })
            .collect()
    }
}

// ============================================================================
// View Methods
// ============================================================================
impl RustPw {
    fn view_startup(&self) -> Element<Message> {
        let icon_handle = image::Handle::from_bytes(include_bytes!("../assets/icon.png").to_vec());
        let icon_image = image(icon_handle).width(128).height(128);

        let content = column![
            vertical_space().height(30),
            icon_image,
            vertical_space().height(20),
            text(APP_NAME).size(48).color(COLOR_ACCENT_YELLOW),
            text(format!("Version {}", APP_VERSION)).size(16).color(COLOR_TEXT_WHITE),
            vertical_space().height(30),
            text("Welcome to RustPw").size(24).color(COLOR_TEXT_WHITE),
            text("A secure password manager").size(16).color(COLOR_ACCENT_CYAN),
            vertical_space().height(40),
            row![
                styled_button("Open Vault", COLOR_ACCENT_CYAN)
                    .on_press(Message::OpenVault)
                    .padding(15),
                horizontal_space().width(20),
                styled_button("Create New", COLOR_ACCENT_GREEN)
                    .on_press(Message::NewVault)
                    .padding(15),
                horizontal_space().width(20),
                styled_button("Exit", COLOR_ACCENT_RED)
                    .on_press(Message::ExitApp)
                    .padding(15),
            ],
        ]
        .spacing(10)
        .align_x(alignment::Horizontal::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .style(container_dark_style)
            .into()
    }

    fn view_main(&self) -> Element<Message> {
        let title_bar = self.view_title_bar();
        let toolbar = self.view_toolbar();
        let search_bar = self.view_search_bar();
        let tabs = self.view_category_tabs();
        let table = self.view_entry_table();
        let status_bar = self.view_status_bar();

        let content = column![title_bar, toolbar, search_bar, tabs, table, status_bar,];

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container_dark_style)
            .into()
    }

    fn view_title_bar(&self) -> Element<Message> {
        let vault_name = self
            .vault_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "No vault open".to_string());

        let modified_indicator = if self.modified { " *" } else { "" };

        let icon_handle = image::Handle::from_bytes(include_bytes!("../assets/icon.png").to_vec());
        let icon_image = image(icon_handle).width(24).height(24);

        row![
            horizontal_space().width(8),
            icon_image,
            text(format!("  {}", APP_NAME))
                .size(16)
                .color(COLOR_ACCENT_YELLOW),
            horizontal_space(),
            text(format!("{}{}", vault_name, modified_indicator))
                .size(12)
                .color(COLOR_ACCENT_CYAN),
            horizontal_space(),
            button(text("-").size(18))
                .padding(5)
                .style(button_transparent_style),
            button(text("X").size(14))
                .padding(5)
                .style(button_close_style)
                .on_press(Message::CloseApp),
        ]
        .padding(10)
        .align_y(alignment::Vertical::Center)
        .height(40)
        .into()
    }

    fn view_toolbar(&self) -> Element<Message> {
        let has_vault = self.vault_data.is_some();

        // Create toolbar buttons inline - matching the working tab button pattern
        let btn_new = button(text("New Vault").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press(Message::NewVault);

        let btn_open = button(text("Open Vault").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press(Message::OpenVault);

        let btn_close = button(text("Close Vault").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::CloseVault));

        let btn_save = button(text("Save").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::SaveVault));

        let btn_category = button(text("+ Category").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::AddCategory));

        let btn_entry = button(text("+ Entry").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::AddEntry));

        let btn_config = button(text("Config").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press(Message::OpenConfig);

        let btn_info = button(text("Vault Info").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::GoToScreen(Screen::VaultProperties)));

        let btn_exit = button(text("Exit").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press(Message::CloseApp);

        let btn_lock = button(text("Lock").size(13))
            .padding([8, 12])
            .style(button_tab_style)
            .on_press_maybe(has_vault.then_some(Message::LockVault));

        row![
            btn_new,
            btn_open,
            btn_close,
            btn_save,
            horizontal_space().width(20),
            btn_category,
            btn_entry,
            horizontal_space().width(20),
            btn_config,
            btn_info,
            btn_exit,
            horizontal_space(),
            btn_lock,
        ]
        .spacing(8)
        .padding(10)
        .into()
    }

    fn view_search_bar(&self) -> Element<Message> {
        row![
            text("Search:").size(14).color(COLOR_TEXT_WHITE),
            text_input("Type to search entries...", &self.search_text)
                .on_input(Message::SearchChanged)
                .padding([10, 12])
                .size(14)
                .width(Length::Fill)
                .style(text_input_style),
        ]
        .spacing(10)
        .padding(10)
        .align_y(alignment::Vertical::Center)
        .into()
    }

    fn view_category_tabs(&self) -> Element<Message> {
        let Some(ref data) = self.vault_data else {
            return container(text("No vault open").color(COLOR_TEXT_WHITE))
                .padding(10)
                .into();
        };

        let mut tabs_row = Row::new().spacing(2);

        let mut categories: Vec<_> = data.categories.keys().collect();
        categories.sort();

        for category in categories {
            let is_selected = self.selected_category.as_ref() == Some(category);
            let cat_name = category.clone();
            let cat_name2 = category.clone();

            let tab_content = row![
                text(category).size(12),
                horizontal_space().width(5),
                button(text("x").size(10))
                    .padding(2)
                    .style(button_tab_close_style)
                    .on_press(Message::DeleteCategory(cat_name2)),
            ]
            .align_y(alignment::Vertical::Center);

            let tab = button(tab_content)
                .padding([10, 15])
                .style(if is_selected {
                    button_tab_selected_style
                } else {
                    button_tab_style
                })
                .on_press(Message::SelectCategory(cat_name));

            tabs_row = tabs_row.push(tab);
        }

        container(
            scrollable(tabs_row)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::default(),
                ))
                .width(Length::Fill),
        )
        .padding(5)
        .height(45)
        .into()
    }

    fn view_entry_table(&self) -> Element<Message> {
        let entries = self.get_filtered_entries();

        if entries.is_empty() {
            let msg = if self.vault_data.is_none() {
                "Open or create a vault to get started"
            } else if self.selected_category.is_none() {
                "Create a category to add entries"
            } else {
                "No entries. Click '+ Entry' to add one."
            };

            return container(text(msg).size(16).color(COLOR_ACCENT_CYAN))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .style(container_dark_style)
                .into();
        }

        // Header row - all columns use FillPortion for responsive sizing
        let header = row![
            text("#").width(Length::FillPortion(1)).color(COLOR_ACCENT_YELLOW),
            text("Name").width(Length::FillPortion(3)).color(COLOR_ACCENT_YELLOW),
            text("Username").width(Length::FillPortion(3)).color(COLOR_ACCENT_YELLOW),
            text("Password").width(Length::FillPortion(3)).color(COLOR_ACCENT_YELLOW),
            text("URL").width(Length::FillPortion(4)).color(COLOR_ACCENT_YELLOW),
            text("Notes").width(Length::FillPortion(4)).color(COLOR_ACCENT_YELLOW),
            text("Actions").width(Length::FillPortion(4)).color(COLOR_ACCENT_YELLOW),
        ]
        .spacing(10)
        .padding([10, 15])
        .align_y(alignment::Vertical::Center);

        // Entry rows
        let mut rows = Column::new().spacing(2);

        for (idx, entry) in entries {
            let password_display = if self.password_visible_rows.contains(&idx) {
                entry.password.clone()
            } else {
                "********".to_string()
            };

            // Create tooltip-enabled text cells that show full content on hover
            let name_cell = tooltip_text_cell(&entry.name, COLOR_TEXT_WHITE, Length::FillPortion(3));
            let username_cell = tooltip_text_cell(&entry.username, COLOR_TEXT_WHITE, Length::FillPortion(3));
            let password_cell = tooltip_text_cell(&password_display, COLOR_ACCENT_GREEN, Length::FillPortion(3));
            let url_cell = tooltip_text_cell(&entry.url, COLOR_ACCENT_CYAN, Length::FillPortion(4));
            let notes_cell = tooltip_text_cell(&entry.notes, COLOR_TEXT_WHITE, Length::FillPortion(4));

            let entry_row = row![
                text(format!("{}", idx + 1))
                    .width(Length::FillPortion(1))
                    .color(COLOR_TEXT_WHITE),
                name_cell,
                username_cell,
                password_cell,
                url_cell,
                notes_cell,
                row![
                    small_button("Eye", COLOR_ACCENT_CYAN)
                        .on_press(Message::TogglePasswordVisibility(idx)),
                    small_button("Copy", COLOR_ACCENT_GREEN).on_press(Message::CopyPassword(idx)),
                    small_button("Edit", COLOR_ACCENT_YELLOW).on_press(Message::EditEntry(idx)),
                    small_button("Del", COLOR_ACCENT_RED).on_press(Message::DeleteEntry(idx)),
                ]
                .spacing(3)
                .width(Length::FillPortion(4)),
            ]
            .spacing(10)
            .padding([8, 15])
            .align_y(alignment::Vertical::Center);

            let entry_container = container(entry_row)
                .width(Length::Fill)
                .style(container_entry_style);

            rows = rows.push(entry_container);
        }

        let table = column![
            container(header).style(container_header_style),
            scrollable(rows).height(Length::Fill),
        ];

        container(table)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(10)
            .style(container_dark_style)
            .into()
    }

    fn view_status_bar(&self) -> Element<Message> {
        let entry_count = self
            .vault_data
            .as_ref()
            .map(|d| d.total_entries())
            .unwrap_or(0);

        row![
            text(&self.status_message).size(11).color(COLOR_ACCENT_GREEN),
            horizontal_space(),
            text(format!("{} entries", entry_count))
                .size(11)
                .color(COLOR_ACCENT_CYAN),
        ]
        .padding([5, 10])
        .height(25)
        .into()
    }

    fn view_locked(&self) -> Element<Message> {
        let vault_name = self
            .vault_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let content = column![
            vertical_space().height(50),
            text("Vault Locked").size(32).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(20),
            text(format!("'{}'", vault_name))
                .size(16)
                .color(COLOR_ACCENT_CYAN),
            vertical_space().height(40),
            row![
                styled_button("Unlock", COLOR_ACCENT_GREEN)
                    .on_press(Message::UnlockVault)
                    .padding(15),
                horizontal_space().width(20),
                styled_button("Open Another", COLOR_ACCENT_CYAN)
                    .on_press(Message::OpenVault)
                    .padding(15),
                horizontal_space().width(20),
                styled_button("Exit", COLOR_ACCENT_RED)
                    .on_press(Message::ExitApp)
                    .padding(15),
            ],
        ]
        .spacing(10)
        .align_x(alignment::Horizontal::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .style(container_dark_style)
            .into()
    }

    fn view_vault_dialog(&self, mode: &VaultDialogMode) -> Element<Message> {
        let title = match mode {
            VaultDialogMode::Create => "Create New Vault",
            VaultDialogMode::Open => "Open Vault",
            VaultDialogMode::Unlock => "Unlock Vault",
        };

        let mut content = column![
            text(title).size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(20),
        ]
        .spacing(10);

        // Vault file path
        content = content.push(
            column![
                text("Vault File:").color(COLOR_TEXT_WHITE),
                row![
                    text_input("Select vault file...", &self.vault_dialog_path)
                        .id(id_vault_path())
                        .on_input(Message::VaultPathChanged)
                        .padding(10)
                        .width(Length::Fill)
                        .style(text_input_style),
                    styled_button("Browse", COLOR_ACCENT_CYAN).on_press(Message::SelectVaultFile),
                ]
                .spacing(10),
            ]
            .spacing(5),
        );

        content = content.push(vertical_space().height(10));

        // Passphrase
        let passphrase_input = if self.vault_dialog_passphrase_visible {
            text_input("Enter passphrase...", &self.vault_dialog_passphrase)
                .id(id_passphrase())
                .on_input(Message::PassphraseChanged)
        } else {
            text_input("Enter passphrase...", &self.vault_dialog_passphrase)
                .id(id_passphrase())
                .on_input(Message::PassphraseChanged)
                .secure(true)
        };

        content = content.push(
            column![
                text("Passphrase:").color(COLOR_TEXT_WHITE),
                row![
                    passphrase_input.padding(10).width(Length::Fill).style(text_input_style),
                    styled_button(
                        if self.vault_dialog_passphrase_visible {
                            "Hide"
                        } else {
                            "Show"
                        },
                        COLOR_ACCENT_CYAN
                    )
                    .on_press(Message::TogglePassphraseVisibility),
                ]
                .spacing(10),
            ]
            .spacing(5),
        );

        // Confirm passphrase (only for create mode)
        if matches!(mode, VaultDialogMode::Create) {
            let confirm_input = if self.vault_dialog_passphrase_visible {
                text_input("Confirm passphrase...", &self.vault_dialog_confirm)
                    .id(id_confirm_passphrase())
                    .on_input(Message::ConfirmPassphraseChanged)
            } else {
                text_input("Confirm passphrase...", &self.vault_dialog_confirm)
                    .id(id_confirm_passphrase())
                    .on_input(Message::ConfirmPassphraseChanged)
                    .secure(true)
            };

            content = content.push(vertical_space().height(10));
            content = content.push(
                column![
                    text("Confirm Passphrase:").color(COLOR_TEXT_WHITE),
                    confirm_input.padding(10).width(Length::Fill).style(text_input_style),
                ]
                .spacing(5),
            );
        }

        // Error message
        if let Some(ref error) = self.vault_dialog_error {
            content = content.push(vertical_space().height(10));
            content = content.push(text(error).color(COLOR_ACCENT_RED));
        }

        content = content.push(vertical_space().height(20));

        // Buttons
        let action_text = match mode {
            VaultDialogMode::Create => "Create",
            VaultDialogMode::Open | VaultDialogMode::Unlock => "Open",
        };

        content = content.push(
            row![
                horizontal_space(),
                styled_button(action_text, COLOR_ACCENT_GREEN).on_press(Message::ConfirmYes),
                horizontal_space().width(10),
                styled_button("Cancel", COLOR_ACCENT_RED).on_press(Message::CloseDialog),
            ]
            .spacing(10),
        );

        dialog_container(content.width(450).into())
    }

    fn view_entry_dialog(&self, mode: &EntryDialogMode) -> Element<Message> {
        let title = match mode {
            EntryDialogMode::Add => "Add Entry",
            EntryDialogMode::Edit { .. } => "Edit Entry",
        };

        let (strength, strength_desc) = PasswordGenerator::calculate_strength(&self.entry_dialog.password);
        let strength_color = match strength {
            0..=29 => Color::from_rgb(1.0, 0.27, 0.27),
            30..=49 => Color::from_rgb(1.0, 0.67, 0.0),
            50..=69 => Color::from_rgb(1.0, 1.0, 0.0),
            70..=89 => Color::from_rgb(0.67, 1.0, 0.0),
            _ => COLOR_ACCENT_GREEN,
        };

        let password_input = if self.entry_dialog_password_visible {
            text_input("Enter password", &self.entry_dialog.password)
                .id(id_entry_password())
                .on_input(Message::EntryPasswordChanged)
        } else {
            text_input("Enter password", &self.entry_dialog.password)
                .id(id_entry_password())
                .on_input(Message::EntryPasswordChanged)
                .secure(true)
        };

        let content = column![
            text(title).size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(15),
            // Name
            column![
                text("Name:").color(COLOR_TEXT_WHITE),
                text_input("e.g., Gmail Account", &self.entry_dialog.name)
                    .id(id_entry_name())
                    .on_input(Message::EntryNameChanged)
                    .padding(8)
                    .style(text_input_style),
            ]
            .spacing(5),
            // Username
            column![
                text("Username:").color(COLOR_TEXT_WHITE),
                text_input("e.g., user@example.com", &self.entry_dialog.username)
                    .id(id_entry_username())
                    .on_input(Message::EntryUsernameChanged)
                    .padding(8)
                    .style(text_input_style),
            ]
            .spacing(5),
            // Password
            column![
                text("Password:").color(COLOR_TEXT_WHITE),
                row![
                    password_input.padding(8).width(Length::Fill).style(text_input_style),
                    small_button(
                        if self.entry_dialog_password_visible {
                            "Hide"
                        } else {
                            "Show"
                        },
                        COLOR_ACCENT_CYAN
                    )
                    .on_press(Message::ToggleEntryPasswordVisibility),
                    small_button("Gen", COLOR_ACCENT_YELLOW).on_press(Message::GenerateEntryPassword),
                ]
                .spacing(5),
            ]
            .spacing(5),
            // Strength
            row![
                text("Strength:").size(12).color(COLOR_TEXT_WHITE),
                progress_bar(0.0..=100.0, strength as f32)
                    .height(15)
                    .width(200),
                text(strength_desc).size(12).color(strength_color),
            ]
            .spacing(10)
            .align_y(alignment::Vertical::Center),
            // URL
            column![
                text("URL:").color(COLOR_TEXT_WHITE),
                text_input("e.g., https://www.example.com", &self.entry_dialog.url)
                    .id(id_entry_url())
                    .on_input(Message::EntryUrlChanged)
                    .padding(8)
                    .style(text_input_style),
            ]
            .spacing(5),
            // Notes
            column![
                text("Notes:").color(COLOR_TEXT_WHITE),
                text_input("Additional notes...", &self.entry_dialog.notes)
                    .id(id_entry_notes())
                    .on_input(Message::EntryNotesChanged)
                    .padding(8)
                    .style(text_input_style),
            ]
            .spacing(5),
            vertical_space().height(15),
            // Buttons
            row![
                horizontal_space(),
                styled_button("Save", COLOR_ACCENT_GREEN).on_press(Message::SaveEntry),
                horizontal_space().width(10),
                styled_button("Cancel", COLOR_ACCENT_RED).on_press(Message::CloseDialog),
            ],
        ]
        .spacing(10)
        .width(500);

        dialog_container(content.into())
    }

    fn view_password_generator(&self) -> Element<Message> {
        let (strength, strength_desc) = PasswordGenerator::calculate_strength(&self.pw_gen_password);
        let strength_color = match strength {
            0..=29 => Color::from_rgb(1.0, 0.27, 0.27),
            30..=49 => Color::from_rgb(1.0, 0.67, 0.0),
            50..=69 => Color::from_rgb(1.0, 1.0, 0.0),
            70..=89 => Color::from_rgb(0.67, 1.0, 0.0),
            _ => COLOR_ACCENT_GREEN,
        };

        let content = column![
            text("Password Generator").size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(15),
            // Length
            row![
                text("Length:").color(COLOR_TEXT_WHITE),
                text_input("", &self.pw_gen_length.to_string())
                    .on_input(Message::PasswordLengthChanged)
                    .padding(5)
                    .width(60)
                    .style(text_input_style),
            ]
            .spacing(10)
            .align_y(alignment::Vertical::Center),
            vertical_space().height(10),
            // Options
            checkbox("Uppercase (A-Z)", self.pw_gen_upper)
                .on_toggle(Message::ToggleUppercase)
                .style(checkbox_style),
            checkbox("Lowercase (a-z)", self.pw_gen_lower)
                .on_toggle(Message::ToggleLowercase)
                .style(checkbox_style),
            checkbox("Digits (0-9)", self.pw_gen_digits)
                .on_toggle(Message::ToggleDigits)
                .style(checkbox_style),
            checkbox("Special (!@#$%...)", self.pw_gen_special)
                .on_toggle(Message::ToggleSpecial)
                .style(checkbox_style),
            checkbox("Exclude ambiguous (0O1lI)", self.pw_gen_exclude_ambiguous)
                .on_toggle(Message::ToggleExcludeAmbiguous)
                .style(checkbox_style),
            vertical_space().height(15),
            // Generated password
            text_input("", &self.pw_gen_password)
                .padding(10)
                .width(Length::Fill)
                .style(text_input_password_style),
            // Strength
            row![
                text("Strength:").size(12).color(COLOR_TEXT_WHITE),
                progress_bar(0.0..=100.0, strength as f32)
                    .height(15)
                    .width(150),
                text(strength_desc).size(12).color(strength_color),
            ]
            .spacing(10)
            .align_y(alignment::Vertical::Center),
            vertical_space().height(15),
            // Buttons
            row![
                styled_button("Regenerate", COLOR_ACCENT_CYAN).on_press(Message::RegeneratePassword),
                horizontal_space().width(10),
                styled_button("Copy", COLOR_ACCENT_GREEN).on_press(Message::CopyPassword(0)),
                horizontal_space().width(10),
                if self.pw_gen_for_entry {
                    styled_button("Use", COLOR_ACCENT_YELLOW).on_press(Message::UseGeneratedPassword)
                } else {
                    styled_button("Close", COLOR_ACCENT_RED).on_press(Message::CloseDialog)
                },
            ],
        ]
        .spacing(8)
        .width(400);

        dialog_container(content.into())
    }

    fn view_config_dialog(&self) -> Element<Message> {
        // Create cipher mode selector buttons
        let cipher_mode_row = row![
            text("Cipher Mode:").width(150).color(COLOR_TEXT_WHITE),
            horizontal_space(),
            cipher_mode_button("CBC", CipherMode::CBC, self.config_edit.aes_mode),
            horizontal_space().width(5),
            cipher_mode_button("CTR", CipherMode::CTR, self.config_edit.aes_mode),
            horizontal_space().width(5),
            cipher_mode_button("GCM", CipherMode::GCM, self.config_edit.aes_mode),
        ]
        .spacing(5)
        .align_y(alignment::Vertical::Center);

        // Key size is fixed at 256 bits
        let key_size_row = row![
            text("Key Size:").width(150).color(COLOR_TEXT_WHITE),
            horizontal_space(),
            text("256 bits").color(COLOR_ACCENT_GREEN),
        ]
        .spacing(10)
        .align_y(alignment::Vertical::Center);

        let content = column![
            text("Configuration").size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(15),
            // AES Settings
            text("Encryption Settings").size(16).color(COLOR_ACCENT_CYAN),
            horizontal_rule(1),
            cipher_mode_row,
            key_size_row,
            config_row(
                "PBKDF2 Iterations:",
                self.config_edit.pbkdf2_iterations.to_string(),
                Message::ConfigIterationsChanged
            ),
            vertical_space().height(10),
            // Application Settings
            text("Application Settings").size(16).color(COLOR_ACCENT_CYAN),
            horizontal_rule(1),
            config_row(
                "Auto-lock (minutes):",
                self.config_edit.auto_lock_minutes.to_string(),
                Message::ConfigAutoLockChanged
            ),
            config_row(
                "Clipboard clear (seconds):",
                self.config_edit.clipboard_clear_seconds.to_string(),
                Message::ConfigClipboardClearChanged
            ),
            config_row(
                "Default password length:",
                self.config_edit.default_password_length.to_string(),
                Message::ConfigPasswordLengthChanged
            ),
            config_row(
                "Max category name length:",
                self.config_edit.max_category_name_length.to_string(),
                Message::ConfigMaxCategoryLengthChanged
            ),
            vertical_space().height(20),
            // Buttons
            row![
                styled_button("Reset Defaults", COLOR_ACCENT_ORANGE)
                    .on_press(Message::ResetConfigDefaults),
                horizontal_space(),
                styled_button("Save", COLOR_ACCENT_GREEN).on_press(Message::SaveConfig),
                horizontal_space().width(10),
                styled_button("Cancel", COLOR_ACCENT_RED).on_press(Message::CloseDialog),
            ],
        ]
        .spacing(8)
        .width(500);

        dialog_container(content.into())
    }

    fn view_vault_properties(&self) -> Element<Message> {
        let vault_name = self
            .vault_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let file_size = self
            .vault_path
            .as_ref()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| format_file_size(m.len()))
            .unwrap_or_else(|| "Unknown".to_string());

        let (version, cipher_mode, key_size, iterations) = if let Some(ref props) = self.vault_properties {
            (
                format!("v{}", props.version),
                format!("AES-256-{}", props.cipher_mode.as_str()),
                format!("{} bits", props.key_size),
                props.iterations.to_string(),
            )
        } else {
            ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string())
        };

        let (created, modified, vault_ver) = if let Some(ref data) = self.vault_data {
            (
                format_datetime(&data.metadata.created),
                format_datetime(&data.metadata.modified),
                data.metadata.version.clone(),
            )
        } else {
            ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string())
        };

        let content = column![
            text("Vault Properties").size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(15),
            // File Info
            text("File Information").size(16).color(COLOR_ACCENT_CYAN),
            horizontal_rule(1),
            property_row("Filename:", vault_name),
            property_row("File Size:", file_size),
            vertical_space().height(10),
            // Encryption Settings
            text("Encryption Settings").size(16).color(COLOR_ACCENT_CYAN),
            horizontal_rule(1),
            property_row("Format Version:", version),
            property_row("Cipher:", cipher_mode),
            property_row("Key Size:", key_size),
            property_row("PBKDF2 Iterations:", iterations),
            vertical_space().height(10),
            // Vault Metadata
            text("Vault Metadata").size(16).color(COLOR_ACCENT_CYAN),
            horizontal_rule(1),
            property_row("Created:", created),
            property_row("Last Modified:", modified),
            property_row("Vault Version:", vault_ver),
            vertical_space().height(20),
            // Close button
            row![
                horizontal_space(),
                styled_button("Close", COLOR_ACCENT_YELLOW).on_press(Message::CloseDialog),
                horizontal_space(),
            ],
        ]
        .spacing(8)
        .width(450);

        dialog_container(content.into())
    }

    fn view_confirm_dialog(&self, title: &str, message: &str) -> Element<Message> {
        let title_owned = title.to_string();
        let message_owned = message.to_string();
        let content = column![
            text(title_owned).size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(20),
            text(message_owned).size(14).color(COLOR_TEXT_WHITE),
            vertical_space().height(30),
            row![
                horizontal_space(),
                styled_button("Yes", COLOR_ACCENT_GREEN).on_press(Message::ConfirmYes),
                horizontal_space().width(10),
                styled_button("No", COLOR_ACCENT_RED).on_press(Message::ConfirmNo),
                horizontal_space().width(10),
                styled_button("Cancel", COLOR_ACCENT_CYAN).on_press(Message::CloseDialog),
            ],
        ]
        .spacing(10)
        .width(400)
        .align_x(alignment::Horizontal::Center);

        dialog_container(content.into())
    }

    fn view_category_input(&self, mode: &CategoryInputMode) -> Element<Message> {
        let title = match mode {
            CategoryInputMode::Add => "Add Category",
            CategoryInputMode::Rename { .. } => "Rename Category",
        };

        let content = column![
            text(title).size(24).color(COLOR_ACCENT_YELLOW),
            vertical_space().height(20),
            text(format!("Category name (max {} chars):", self.config.max_category_name_length))
                .color(COLOR_TEXT_WHITE),
            text_input("Enter category name...", &self.category_input)
                .id(id_category_name())
                .on_input(Message::CategoryNameChanged)
                .on_submit(Message::ConfirmCategoryAction)
                .padding(10)
                .style(text_input_style),
            vertical_space().height(20),
            row![
                horizontal_space(),
                styled_button("OK", COLOR_ACCENT_GREEN).on_press(Message::ConfirmYes),
                horizontal_space().width(10),
                styled_button("Cancel", COLOR_ACCENT_RED).on_press(Message::CloseDialog),
            ],
        ]
        .spacing(10)
        .width(400);

        dialog_container(content.into())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Creates a text cell with tooltip that shows full content on hover
fn tooltip_text_cell(content: &str, color: Color, width: Length) -> Element<'static, Message> {
    let display_text = content.to_string();
    let tooltip_text = content.to_string();

    if content.is_empty() {
        return container(text("").color(color))
            .width(width)
            .into();
    }

    // Create the tooltip with full content shown on hover
    tooltip(
        container(text(display_text).color(color))
            .width(width)
            .clip(true),
        container(
            text(tooltip_text)
                .color(COLOR_ACCENT_YELLOW)
        )
        .padding(8)
        .style(|_theme| container::Style {
            background: Some(iced::Background::Color(COLOR_BG_TITLE)),
            border: iced::Border {
                color: COLOR_ACCENT_YELLOW,
                width: 1.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        }),
        tooltip::Position::Bottom,
    )
    .gap(5)
    .into()
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} bytes", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_datetime(iso: &str) -> String {
    iso.get(..19)
        .map(|s| s.replace('T', " "))
        .unwrap_or_else(|| iso.to_string())
}

// ============================================================================
// Styling Functions
// ============================================================================
fn container_dark_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(COLOR_BG_DARK.into()),
        text_color: Some(COLOR_TEXT_WHITE),
        ..Default::default()
    }
}

fn container_header_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(COLOR_BG_TITLE.into()),
        text_color: Some(COLOR_ACCENT_YELLOW),
        ..Default::default()
    }
}

fn container_entry_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.3).into()),
        text_color: Some(COLOR_TEXT_WHITE),
        border: iced::Border {
            color: Color::from_rgb(0.2, 0.2, 0.4),
            width: 1.0,
            radius: 3.0.into(),
        },
        ..Default::default()
    }
}

fn container_dialog_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(COLOR_BG_DARK.into()),
        text_color: Some(COLOR_TEXT_WHITE),
        border: iced::Border {
            color: COLOR_ACCENT_YELLOW,
            width: 2.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

fn text_input_style(_theme: &Theme, _status: text_input::Status) -> text_input::Style {
    text_input::Style {
        background: COLOR_BG_BLACK.into(),
        border: iced::Border {
            color: COLOR_ACCENT_CYAN,
            width: 2.0,
            radius: 5.0.into(),
        },
        icon: COLOR_TEXT_WHITE,
        placeholder: Color::from_rgb(0.5, 0.5, 0.5),
        value: COLOR_TEXT_WHITE,
        selection: COLOR_ACCENT_CYAN,
    }
}

fn text_input_password_style(_theme: &Theme, _status: text_input::Status) -> text_input::Style {
    text_input::Style {
        background: COLOR_BG_BLACK.into(),
        border: iced::Border {
            color: COLOR_ACCENT_CYAN,
            width: 2.0,
            radius: 5.0.into(),
        },
        icon: COLOR_TEXT_WHITE,
        placeholder: Color::from_rgb(0.5, 0.5, 0.5),
        value: COLOR_ACCENT_GREEN,
        selection: COLOR_ACCENT_CYAN,
    }
}

fn checkbox_style(_theme: &Theme, _status: checkbox::Status) -> checkbox::Style {
    checkbox::Style {
        background: COLOR_BG_BLACK.into(),
        icon_color: COLOR_ACCENT_GREEN,
        border: iced::Border {
            color: COLOR_ACCENT_CYAN,
            width: 1.0,
            radius: 3.0.into(),
        },
        text_color: Some(COLOR_TEXT_WHITE),
    }
}

fn styled_button<'a>(label: &'a str, color: Color) -> button::Button<'a, Message> {
    button(
        row![text(label).size(14).color(color)]
            .align_y(alignment::Vertical::Center)
    )
    .padding([10, 15])
    .style(move |_theme, status| {
        let base = button::Style {
            background: Some(COLOR_BG_TITLE.into()),
            text_color: color,
            border: iced::Border {
                color,
                width: 2.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        };
        match status {
            button::Status::Hovered => button::Style {
                background: Some(COLOR_HOVER.into()),
                ..base
            },
            _ => base,
        }
    })
}

fn styled_button_conditional<'a>(label: &'a str, color: Color, enabled: bool) -> button::Button<'a, Message> {
    let display_color = if enabled { color } else { COLOR_TEXT_DIM };
    button(
        row![text(label).size(14).color(display_color)]
            .align_y(alignment::Vertical::Center)
    )
    .padding([10, 15])
    .style(move |_theme, status| {
        let base = button::Style {
            background: Some(COLOR_BG_TITLE.into()),
            text_color: display_color,
            border: iced::Border {
                color: display_color,
                width: 2.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        };
        match status {
            button::Status::Hovered if enabled => button::Style {
                background: Some(COLOR_HOVER.into()),
                ..base
            },
            _ => base,
        }
    })
}

fn small_button<'a>(label: &'a str, color: Color) -> button::Button<'a, Message> {
    button(text(label).size(11).color(color))
    .padding([5, 8])
    .width(Length::Shrink)
    .style(move |_theme, status| {
        let base = button::Style {
            background: Some(COLOR_BG_TITLE.into()),
            text_color: color,
            border: iced::Border {
                color,
                width: 1.0,
                radius: 3.0.into(),
            },
            ..Default::default()
        };
        match status {
            button::Status::Hovered => button::Style {
                background: Some(COLOR_HOVER.into()),
                ..base
            },
            _ => base,
        }
    })
}

fn button_colored_style(status: button::Status, color: Color) -> button::Style {
    let base = button::Style {
        background: Some(COLOR_BG_TITLE.into()),
        text_color: color,
        border: iced::Border {
            color,
            width: 2.0,
            radius: 5.0.into(),
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(COLOR_HOVER.into()),
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(Color::from_rgb(0.1, 0.1, 0.3).into()),
            ..base
        },
        _ => base,
    }
}

fn button_small_style(status: button::Status, color: Color) -> button::Style {
    let base = button::Style {
        background: Some(COLOR_BG_TITLE.into()),
        text_color: color,
        border: iced::Border {
            color,
            width: 1.0,
            radius: 3.0.into(),
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(COLOR_HOVER.into()),
            ..base
        },
        _ => base,
    }
}

fn button_transparent_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: None,
        text_color: COLOR_TEXT_WHITE,
        border: iced::Border::default(),
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(Color::from_rgb(0.2, 0.2, 0.4).into()),
            ..base
        },
        _ => base,
    }
}

fn button_close_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: None,
        text_color: COLOR_TEXT_WHITE,
        border: iced::Border::default(),
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(Color::from_rgb(1.0, 0.27, 0.27).into()),
            ..base
        },
        _ => base,
    }
}

fn button_tab_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(COLOR_BG_TITLE.into()),
        text_color: COLOR_TEXT_WHITE,
        border: iced::Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 5.0.into(),
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(COLOR_HOVER.into()),
            ..base
        },
        _ => base,
    }
}

fn button_tab_selected_style(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: Some(COLOR_BG_DARK.into()),
        text_color: COLOR_ACCENT_YELLOW,
        border: iced::Border {
            color: COLOR_ACCENT_CYAN,
            width: 2.0,
            radius: 5.0.into(),
        },
        ..Default::default()
    }
}

fn button_tab_close_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: None,
        text_color: COLOR_TEXT_WHITE,
        border: iced::Border::default(),
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            text_color: COLOR_ACCENT_RED,
            ..base
        },
        _ => base,
    }
}

fn dialog_container(content: Element<Message>) -> Element<Message> {
    container(
        container(content)
            .padding(20)
            .style(container_dialog_style),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .style(|_| container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
        ..Default::default()
    })
    .into()
}

fn cipher_mode_button(label: &'static str, mode: CipherMode, current: CipherMode) -> Element<'static, Message> {
    let is_selected = mode == current;
    let color = if is_selected { COLOR_ACCENT_GREEN } else { COLOR_ACCENT_YELLOW };

    button(text(label).color(if is_selected { COLOR_BG_DARK } else { color }))
        .padding(5)
        .style(move |theme, status| {
            if is_selected {
                button::Style {
                    background: Some(iced::Background::Color(COLOR_ACCENT_GREEN)),
                    text_color: COLOR_BG_DARK,
                    border: iced::Border {
                        color: COLOR_ACCENT_GREEN,
                        width: 2.0,
                        radius: 5.0.into(),
                    },
                    ..button::Style::default()
                }
            } else {
                match status {
                    button::Status::Hovered => button::Style {
                        background: Some(iced::Background::Color(COLOR_HOVER)),
                        text_color: COLOR_ACCENT_YELLOW,
                        border: iced::Border {
                            color: COLOR_ACCENT_YELLOW,
                            width: 2.0,
                            radius: 5.0.into(),
                        },
                        ..button::Style::default()
                    },
                    _ => button::Style {
                        background: Some(iced::Background::Color(COLOR_BG_TITLE)),
                        text_color: COLOR_ACCENT_YELLOW,
                        border: iced::Border {
                            color: COLOR_ACCENT_YELLOW,
                            width: 2.0,
                            radius: 5.0.into(),
                        },
                        ..button::Style::default()
                    },
                }
            }
        })
        .on_press(Message::ConfigCipherModeChanged(mode))
        .into()
}

fn config_row(
    label: &'static str,
    value: String,
    on_change: fn(String) -> Message,
) -> Element<'static, Message> {
    row![
        text(label).width(200).color(COLOR_TEXT_WHITE),
        horizontal_space(),
        text_input("", &value)
            .on_input(on_change)
            .padding(5)
            .width(120)
            .style(text_input_style),
    ]
    .spacing(10)
    .align_y(alignment::Vertical::Center)
    .into()
}

fn property_row(label: &'static str, value: String) -> Element<'static, Message> {
    row![
        text(label).width(150).color(COLOR_TEXT_WHITE),
        horizontal_space(),
        text(value).color(COLOR_ACCENT_GREEN),
    ]
    .spacing(10)
    .into()
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn load_icon() -> Option<window::Icon> {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let img = ::image::load_from_memory(icon_bytes).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    window::icon::from_rgba(img.into_raw(), width, height).ok()
}

fn main() -> iced::Result {
    let mut app = iced::application(RustPw::title, RustPw::update, RustPw::view)
        .subscription(RustPw::subscription)
        .theme(RustPw::theme)
        .window_size(iced::Size::new(WINDOW_WIDTH as f32, WINDOW_HEIGHT as f32))
        .default_font(Font::MONOSPACE)
        .exit_on_close_request(false);

    if let Some(icon) = load_icon() {
        app = app.window(window::Settings {
            icon: Some(icon),
            ..Default::default()
        });
    }

    app.run_with(RustPw::new)
}
