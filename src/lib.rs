// SPDX-License-Identifier: GPL-3.0-only
//
//! BobbaXtra — Habbo Origins crypto Xtra, as a dirplayer-rs xtra-sdk plugin.
//!
//! Implements the Lingo crypto session originally exposed by the native
//! `BobbaXtra.x32`: finite-field Diffie-Hellman (with the hard-coded
//! 438-bit prime and generator from sub_10006370 / sub_10006440), HKDF-SHA256
//! key derivation ("BobbaXtraHKDFSalt" + per-direction info strings), and
//! ChaCha20 (no MAC) for the four encrypt/decrypt directions.
//!
//! The four crypto primitives (`chacha20`, `dh`, `hkdf`, `sha256`) are
//! standalone modules with no host coupling — they can be cargo-tested
//! natively against FIPS / RFC 4231 / RFC 5869 / RFC 7539 vectors.

pub mod chacha20;
pub mod dh;
pub mod hkdf;
pub mod sha256;

use base64::Engine;
use num::BigUint;

use xtra_sdk::host_env;
use xtra_sdk::plugin::{XtraInstance, XtraPlugin, XtraResult};
use xtra_sdk::Datum;

use crate::chacha20::ChaCha20Direction;
use crate::dh::PUBLIC_KEY_BYTES;
use crate::hkdf::{hkdf_expand, hkdf_extract};

const HKDF_SALT: &[u8] = b"BobbaXtraHKDFSalt";
const HKDF_INFO_C2S_DATA: &[u8] = b"BobbaXtra|bobba-c2s-data";
const HKDF_INFO_C2S_HEADER: &[u8] = b"BobbaXtra|bobba-c2s-header";
const HKDF_INFO_S2C_DATA: &[u8] = b"BobbaXtra|bobba-s2c-data";
const HKDF_INFO_S2C_HEADER: &[u8] = b"BobbaXtra|bobba-s2c-header";

#[derive(Clone, Copy)]
enum Direction {
    C2sData,
    C2sHeader,
    S2cData,
    S2cHeader,
}

impl Direction {
    fn info(self) -> &'static [u8] {
        match self {
            Direction::C2sData => HKDF_INFO_C2S_DATA,
            Direction::C2sHeader => HKDF_INFO_C2S_HEADER,
            Direction::S2cData => HKDF_INFO_S2C_DATA,
            Direction::S2cHeader => HKDF_INFO_S2C_HEADER,
        }
    }
}

struct Session {
    shared_secret: [u8; PUBLIC_KEY_BYTES],
    c2s_data: ChaCha20Direction,
    c2s_header: ChaCha20Direction,
    s2c_data: ChaCha20Direction,
    s2c_header: ChaCha20Direction,
    counter_c2s_data: u64,
    counter_c2s_header: u64,
    counter_s2c_data: u64,
    counter_s2c_header: u64,
}

impl Session {
    fn derive(shared: [u8; PUBLIC_KEY_BYTES]) -> Self {
        let prk = hkdf_extract(HKDF_SALT, &shared);
        let derive = |d: Direction| -> ChaCha20Direction {
            let mut okm = [0u8; 44];
            hkdf_expand(&prk, d.info(), &mut okm);
            ChaCha20Direction::from_okm(&okm)
        };
        Session {
            shared_secret: shared,
            c2s_data: derive(Direction::C2sData),
            c2s_header: derive(Direction::C2sHeader),
            s2c_data: derive(Direction::S2cData),
            s2c_header: derive(Direction::S2cHeader),
            counter_c2s_data: 0,
            counter_c2s_header: 0,
            counter_s2c_data: 0,
            counter_s2c_header: 0,
        }
    }
}

pub struct BobbaXtraInstance {
    private_key: Option<BigUint>,
    session: Option<Session>,
    last_error: String,
}

impl BobbaXtraInstance {
    pub fn new() -> Self {
        BobbaXtraInstance {
            private_key: None,
            session: None,
            last_error: String::new(),
        }
    }

    fn reset(&mut self) {
        self.private_key = None;
        self.session = None;
        self.last_error.clear();
    }

    fn set_error(&mut self, msg: &str) {
        self.last_error = msg.to_string();
    }

    fn generate_public_key(&mut self) -> Result<String, &'static str> {
        let raw_vec = host_env::random_fill(PUBLIC_KEY_BYTES)
            .map_err(|_| "Unable to gather entropy")?;
        if raw_vec.len() != PUBLIC_KEY_BYTES {
            return Err("Host returned wrong-sized random buffer");
        }
        let mut raw = [0u8; PUBLIC_KEY_BYTES];
        raw.copy_from_slice(&raw_vec);
        let p = dh::prime();
        let g = dh::generator();
        let x = dh::private_key_from_random(&raw, &p);
        let y = g.modpow(&x, &p);
        let pub_dec = dh::to_decimal(&y);
        diag_log(format!(
            "[bobba] generate_public_key: pub={} (len={})",
            pub_dec,
            pub_dec.len()
        ));
        self.private_key = Some(x);
        Ok(pub_dec)
    }

    fn set_server_public_key(&mut self, server_dec: &str) -> bool {
        let private = match self.private_key.as_ref() {
            Some(x) => x.clone(),
            None => {
                self.set_error("Client private key not initialised");
                return false;
            }
        };
        if server_dec.trim().is_empty() {
            self.set_error("Server public key missing");
            return false;
        }
        let y_server = match dh::parse_decimal(server_dec) {
            Some(v) => v,
            None => {
                self.set_error("Server public key missing");
                return false;
            }
        };
        let p = dh::prime();
        if !dh::is_valid_public_key(&y_server, &p) {
            self.set_error("Server public key outside valid range");
            return false;
        }
        let shared = y_server.modpow(&private, &p);
        let shared_bytes = dh::to_fixed_be(&shared);
        let shared_hex: String = shared_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        diag_log(format!(
            "[bobba] set_server_public_key: server_pub_len={} shared_hex={}",
            server_dec.len(),
            shared_hex
        ));
        // BobbaXtra zeroes the private key once the session is established.
        self.private_key = None;
        let session = Session::derive(shared_bytes);
        diag_log(format!(
            "[bobba] derived directions:\n  c2s_data : key={} prefix={:08x} base={:016x}\n  c2s_hdr  : key={} prefix={:08x} base={:016x}\n  s2c_data : key={} prefix={:08x} base={:016x}\n  s2c_hdr  : key={} prefix={:08x} base={:016x}",
            hex_u32_key(&session.c2s_data),   session.c2s_data.nonce_prefix(),   session.c2s_data.nonce_base(),
            hex_u32_key(&session.c2s_header), session.c2s_header.nonce_prefix(), session.c2s_header.nonce_base(),
            hex_u32_key(&session.s2c_data),   session.s2c_data.nonce_prefix(),   session.s2c_data.nonce_base(),
            hex_u32_key(&session.s2c_header), session.s2c_header.nonce_prefix(), session.s2c_header.nonce_base(),
        ));
        self.session = Some(session);
        true
    }

    fn is_ready(&self) -> bool {
        self.session.is_some()
    }

    fn shared_key_hex(&self) -> String {
        match &self.session {
            Some(s) => s.shared_secret.iter().map(|b| format!("{:02x}", b)).collect(),
            None => String::new(),
        }
    }

    fn counter_for(&self, dir: Direction) -> u64 {
        match (&self.session, dir) {
            (Some(s), Direction::C2sData) => s.counter_c2s_data,
            (Some(s), Direction::C2sHeader) => s.counter_c2s_header,
            (Some(s), Direction::S2cData) => s.counter_s2c_data,
            (Some(s), Direction::S2cHeader) => s.counter_s2c_header,
            (None, _) => 0,
        }
    }

    fn xor_message(&mut self, dir: Direction, mut data: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        let session = self.session.as_mut().ok_or("Crypto session not ready")?;
        let (chacha, counter) = match dir {
            Direction::C2sData => (&session.c2s_data, &mut session.counter_c2s_data),
            Direction::C2sHeader => (&session.c2s_header, &mut session.counter_c2s_header),
            Direction::S2cData => (&session.s2c_data, &mut session.counter_s2c_data),
            Direction::S2cHeader => (&session.s2c_header, &mut session.counter_s2c_header),
        };
        chacha.xor(*counter, &mut data);
        *counter = counter.wrapping_add(1);
        Ok(data)
    }
}

fn hex_u32_key(dir: &ChaCha20Direction) -> String {
    dir.key_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Route diagnostics through the host so they appear in the browser
/// console. `log::debug!` isn't wired up in plugin context.
#[inline]
fn diag_log(msg: String) {
    host_env::log(&msg);
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s: String = bytes[..take].iter().map(|b| format!("{:02x}", b)).collect();
    if bytes.len() > max {
        s.push('…');
    }
    s
}

/// Director Lingo strings carry arbitrary bytes; dirplayer-rs shuttles
/// them through Rust `String` using a Latin-1 mapping (byte b → char(b)).
/// This matches the multiuser xtra and js_lingo builtins.
fn string_to_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

fn bytes_to_string(b: &[u8]) -> String {
    b.iter().map(|&byte| byte as char).collect()
}

/// `Device_GetMachineId` reimplementation matching `sub_100044A0` in the
/// BobbaXtra binary. Native flow gathers volume serials, CPU/RAM info,
/// CPUID and MAC addresses, hashes them with SHA-256, packs the result
/// into 12 bytes (`[os_type, hash[0..9], crc16_be]`), base32-encodes with
/// a custom no-ILO0/1 alphabet, then formats as
/// `BX<o>-XXXX-XXXX-XXXX-XXXX-XXXX`.
///
/// In the browser we don't have access to the underlying system data, so
/// we substitute a stable random nonce kept in `localStorage` so the
/// resulting ID stays constant across sessions (the same machine always
/// reports the same id, which is what the server's anti-abuse layer
/// expects).
fn machine_id() -> String {
    const STORAGE_KEY: &str = "dirplayer_bobba_machine_id_seed";
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    // -- Step 1: gather a stable 32-byte fingerprint source from localStorage.
    let mut seed = [0u8; 32];
    let mut have_seed = false;
    if let Some(existing) = host_env::storage_get(STORAGE_KEY) {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(&existing) {
            if bytes.len() == 32 {
                seed.copy_from_slice(&bytes);
                have_seed = true;
            }
        }
    }
    if !have_seed {
        match host_env::random_fill(32) {
            Ok(bytes) if bytes.len() == 32 => seed.copy_from_slice(&bytes),
            _ => {
                // Last-resort deterministic seed so we still return *something*
                // structured rather than panicking.
                seed = [0xCD; 32];
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(seed);
        let _ = host_env::storage_set(STORAGE_KEY, &encoded);
    }

    // -- Step 2: SHA-256 over the fingerprint source.
    let hash = sha256::sha256(&seed);

    // -- Step 3: pack 12 bytes. os_type = 1 (not Wine) for the browser host.
    let mut packed = [0u8; 12];
    packed[0] = 1;
    packed[1..10].copy_from_slice(&hash[0..9]);
    let crc = crc16_ccitt(&packed[0..10]);
    packed[10] = (crc >> 8) as u8;
    packed[11] = (crc & 0xFF) as u8;

    // -- Step 4: base32-encode the 12 bytes into exactly 20 chars (96 bits
    // → 19 full chars + 1 padding char built from the leftover 1 bit).
    let mut encoded = [0u8; 20];
    base32_no_il_o01(&packed, &mut encoded, ALPHABET);

    // -- Step 5: "BX" + '1' + "-XXXX-XXXX-XXXX-XXXX-XXXX".
    let mut out = String::with_capacity(28);
    out.push_str("BX");
    out.push('1'); // browser host is always "not Wine".
    for (i, &b) in encoded.iter().enumerate() {
        if i % 4 == 0 {
            out.push('-');
        }
        out.push(b as char);
    }
    out
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, no xor-out),
/// matching `sub_10003960` in the binary.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// MSB-first base32 encode using a 32-char alphabet. Pads partial trailing
/// bits to a full 5-bit group (matching the binary's loop in sub_100039F0).
/// `out` must be sized for `ceil(data.len() * 8 / 5)` bytes — for the 12
/// input bytes used by Device_GetMachineId that's exactly 20.
fn base32_no_il_o01(data: &[u8], out: &mut [u8], alphabet: &[u8; 32]) {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut pos = 0;
    for &b in data {
        accumulator = (accumulator << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            let idx = ((accumulator >> (bits - 5)) & 0x1F) as usize;
            out[pos] = alphabet[idx];
            pos += 1;
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((accumulator << (5 - bits)) & 0x1F) as usize;
        out[pos] = alphabet[idx];
        pos += 1;
    }
    // The binary pads to 20 chars with 'A' (alphabet[0]) and truncates to 20.
    // For our 12-byte input we always end at exactly 20 (96 bits = 19 full
    // + 1 leftover) so neither branch fires; assert in debug to catch drift.
    while pos < out.len() {
        out[pos] = alphabet[0];
        pos += 1;
    }
}

// ── Cipher dispatch (encrypt + decrypt for both directions) ──────────────

/// BobbaXtra cipher pipeline (matches sub_1000D270/D110 for encrypt,
/// sub_1000CE90/CFD0 for decrypt):
///   Encrypt: plaintext bytes → ChaCha20 XOR → Base64-encode (no padding) → wire string
///   Decrypt: wire string → Base64-decode → ChaCha20 XOR → plaintext bytes
///
/// `is_decrypt` selects which direction of the pipeline to run.
fn cipher_call(
    args: &[Datum],
    instance: &mut BobbaXtraInstance,
    dir: Direction,
    is_decrypt: bool,
) -> XtraResult<Datum> {
    let input = args
        .first()
        .and_then(|d| d.as_str())
        .ok_or_else(|| "Crypto cipher handler requires a string argument".to_string())?;
    let counter_before = instance.counter_for(dir);
    let dir_name = match dir {
        Direction::C2sData => "c2s_data",
        Direction::C2sHeader => "c2s_hdr",
        Direction::S2cData => "s2c_data",
        Direction::S2cHeader => "s2c_hdr",
    };
    let input_bytes_for_xor: Vec<u8> = if is_decrypt {
        // Decrypt: base64 → cipher bytes → XOR → plaintext.
        match base64_decode(input) {
            Ok(b) => b,
            Err(_) => {
                diag_log(format!(
                    "[bobba] {} DECODE-ERR input_len={}",
                    dir_name,
                    input.len()
                ));
                instance.set_error("Base64 decode failed");
                return Ok(Datum::String(String::new()));
            }
        }
    } else {
        // Encrypt: plaintext string → bytes → XOR.
        string_to_bytes(input)
    };
    let in_hex = hex_preview(&input_bytes_for_xor, 32);
    match instance.xor_message(dir, input_bytes_for_xor) {
        Ok(out) => {
            let out_hex = hex_preview(&out, 32);
            let result_string = if is_decrypt {
                // XOR output IS the plaintext — return as Lingo string.
                bytes_to_string(&out)
            } else {
                // XOR output is cipher bytes — base64-encode for the wire.
                base64_encode(&out)
            };
            diag_log(format!(
                "[bobba] {} ctr={} {}={} {}={}",
                dir_name,
                counter_before,
                if is_decrypt { "cipher" } else { "plain" },
                in_hex,
                if is_decrypt { "plain" } else { "wire" },
                if is_decrypt { out_hex } else { result_string.clone() }
            ));
            Ok(Datum::String(result_string))
        }
        Err(msg) => {
            diag_log(format!("[bobba] {} XOR-ERR: {} (in={})", dir_name, msg, in_hex));
            instance.set_error(msg);
            Ok(Datum::String(String::new()))
        }
    }
}

/// Standard Base64 alphabet (matches the table at file offset 0x23420 in
/// BobbaXtra.x32). The binary emits **no padding** `=` chars — it skips the
/// trailing emits when the input doesn't fill a 3-byte group (verified in
/// sub_10002DA0). We do the same.
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(BASE64_ALPHABET[((b0 & 0xFC) >> 2) as usize]);
        out.push(BASE64_ALPHABET[(((b0 & 0x03) << 4) | ((b1 & 0xF0) >> 4)) as usize]);
        if i + 1 < data.len() {
            out.push(BASE64_ALPHABET[(((b1 & 0x0F) << 2) | ((b2 & 0xC0) >> 6)) as usize]);
        }
        if i + 2 < data.len() {
            out.push(BASE64_ALPHABET[(b2 & 0x3F) as usize]);
        }
        i += 3;
    }
    // Safety: BASE64_ALPHABET is ASCII, so every pushed byte is valid UTF-8.
    String::from_utf8(out).unwrap()
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Build inverse alphabet table on the fly. 0xFF marks invalid input.
    let mut inv = [0xFFu8; 256];
    for (idx, &c) in BASE64_ALPHABET.iter().enumerate() {
        inv[c as usize] = idx as u8;
    }
    let chars: Vec<u8> = input.chars().map(|c| c as u8).collect();
    let mut out = Vec::with_capacity(chars.len() * 3 / 4 + 2);
    let mut i = 0;
    while i < chars.len() {
        let take = (chars.len() - i).min(4);
        let mut group = [0u8; 4];
        for j in 0..take {
            let v = inv[chars[i + j] as usize];
            if v == 0xFF {
                return Err(());
            }
            group[j] = v;
        }
        // Decode whatever 6-bit slots we filled.
        if take >= 2 {
            out.push((group[0] << 2) | (group[1] >> 4));
        }
        if take >= 3 {
            out.push((group[1] << 4) | (group[2] >> 2));
        }
        if take >= 4 {
            out.push((group[2] << 6) | group[3]);
        }
        // `take == 1` is a malformed trailing char — shouldn't happen on
        // BobbaXtra output but fall through quietly (no byte produced).
        i += take;
    }
    Ok(out)
}

// ── xtra-sdk wiring ──────────────────────────────────────────────────────

pub struct BobbaXtraPlugin;

impl XtraPlugin for BobbaXtraPlugin {
    type Instance = BobbaXtraInstance;

    fn xtra_name() -> &'static str {
        "BobbaXtra"
    }

    fn create_instance(_args: &[Datum]) -> XtraResult<BobbaXtraInstance> {
        Ok(BobbaXtraInstance::new())
    }

    // BobbaXtra has no static handlers — every Lingo entry point is an
    // instance method on the crypto session.
}

impl XtraInstance for BobbaXtraInstance {
    fn call_handler(&mut self, name: &str, args: &[Datum]) -> XtraResult<Datum> {
        // The host already lowercases `name` before calling. Match
        // lowercased Director names directly.
        match name {
            "crypto_reset" => {
                self.reset();
                Ok(Datum::Void)
            }
            "crypto_generatepublickey" => match self.generate_public_key() {
                Ok(pubkey) => Ok(Datum::String(pubkey)),
                Err(msg) => {
                    self.set_error(msg);
                    Ok(Datum::String(String::new()))
                }
            },
            "crypto_setserverpublickey" => {
                let server_key = args
                    .first()
                    .and_then(|d| d.as_str())
                    .ok_or_else(|| {
                        "Crypto_SetServerPublicKey requires a string argument".to_string()
                    })?;
                let ok = self.set_server_public_key(server_key);
                Ok(Datum::Int(if ok { 1 } else { 0 }))
            }
            "crypto_isready" => Ok(Datum::Int(if self.is_ready() { 1 } else { 0 })),
            "crypto_encryptpayload" => cipher_call(args, self, Direction::C2sData, false),
            "crypto_encryptheader" => cipher_call(args, self, Direction::C2sHeader, false),
            "crypto_decryptpayload" => cipher_call(args, self, Direction::S2cData, true),
            "crypto_decryptheader" => cipher_call(args, self, Direction::S2cHeader, true),
            "crypto_getsharedkeyhex" => Ok(Datum::String(self.shared_key_hex())),
            "crypto_getlasterror" => Ok(Datum::String(self.last_error.clone())),
            "device_getmachineid" => Ok(Datum::String(machine_id())),
            other => Err(format!("BobbaXtra: unknown handler {}", other)),
        }
    }
}

xtra_sdk::export_plugin!(BobbaXtraPlugin);

// The xtra-sdk references `dx_host_call` as a wasm-import; on any non-wasm
// build (cargo check / cargo test / native cdylib) the linker can't find
// that symbol. Provide a no-op stub for non-wasm targets so the lib links;
// the wasm build keeps the real import from the host. Tests that exercise
// host services (`generate_public_key`, `machine_id`) would hit this stub
// and return Void — those tests are intentionally avoided below.
#[cfg(not(target_arch = "wasm32"))]
#[unsafe(no_mangle)]
extern "C" fn dx_host_call(_op: u32, _ptr: *const u8, _len: u32) -> u64 {
    0
}

// ── Tests (cargo test — runs natively, not via wasm) ─────────────────────
//
// The crypto round-trip tests don't go through the host at all (no
// generate_public_key, no machine_id), so they work natively. Handler-level
// integration testing happens in dirplayer-rs.

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_pair() -> (BobbaXtraInstance, BobbaXtraInstance) {
        // Hand-derive shared secrets without going through random_fill,
        // which would need a host. We pick two arbitrary fixed private
        // keys and run the DH math directly, then feed Session::derive.
        let p = dh::prime();
        let g = dh::generator();
        let x_client = BigUint::parse_bytes(
            b"123456789012345678901234567890123456789012345678901234567890",
            10,
        )
        .unwrap()
            % &p;
        let x_server = BigUint::parse_bytes(
            b"987654321098765432109876543210987654321098765432109876543210",
            10,
        )
        .unwrap()
            % &p;
        let y_client = g.modpow(&x_client, &p);
        let y_server = g.modpow(&x_server, &p);
        let shared_c = y_server.modpow(&x_client, &p);
        let shared_s = y_client.modpow(&x_server, &p);
        assert_eq!(shared_c, shared_s);
        let shared_bytes = dh::to_fixed_be(&shared_c);

        let mut client = BobbaXtraInstance::new();
        let mut server = BobbaXtraInstance::new();
        client.session = Some(Session::derive(shared_bytes));
        server.session = Some(Session::derive(shared_bytes));
        (client, server)
    }

    #[test]
    fn key_exchange_and_xor_round_trip() {
        let (mut client, mut server) = make_session_pair();
        assert!(client.is_ready());
        assert!(server.is_ready());
        assert_eq!(client.shared_key_hex(), server.shared_key_hex());

        // Client -> Server payload
        let plaintext = b"hello bobba".to_vec();
        let ct = client
            .xor_message(Direction::C2sData, plaintext.clone())
            .unwrap();
        assert_ne!(ct, plaintext);
        let dec = server.xor_message(Direction::C2sData, ct).unwrap();
        assert_eq!(dec, plaintext);

        // Server -> Client header
        let header = b"\x00\x01\x02\x03\xFF".to_vec();
        let ct = server
            .xor_message(Direction::S2cHeader, header.clone())
            .unwrap();
        let dec = client.xor_message(Direction::S2cHeader, ct).unwrap();
        assert_eq!(dec, header);
    }

    #[test]
    fn rejects_out_of_range_server_key() {
        let mut client = BobbaXtraInstance::new();
        // Hand-seed a private key so set_server_public_key gets past the
        // "Client private key not initialised" check.
        client.private_key = Some(BigUint::from(42u32));
        assert!(!client.set_server_public_key("0"));
        assert_eq!(client.last_error, "Server public key outside valid range");
        assert!(!client.set_server_public_key(""));
        assert_eq!(client.last_error, "Server public key missing");
    }

    #[test]
    fn rejects_set_server_before_generate() {
        let mut client = BobbaXtraInstance::new();
        assert!(!client.set_server_public_key("3"));
        assert_eq!(client.last_error, "Client private key not initialised");
    }

    #[test]
    fn base64_round_trip() {
        // Empty → empty.
        assert_eq!(base64_encode(&[]), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());

        // RFC 4648 §10 test vectors (no padding — BobbaXtra omits `=`).
        let cases: &[(&[u8], &str)] = &[
            (b"f",      "Zg"),
            (b"fo",     "Zm8"),
            (b"foo",    "Zm9v"),
            (b"foob",   "Zm9vYg"),
            (b"fooba",  "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, enc) in cases {
            assert_eq!(base64_encode(bytes), *enc, "encode {:?}", bytes);
            assert_eq!(base64_decode(enc).unwrap(), *bytes, "decode {}", enc);
        }

        // Round-trip on full-byte range.
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn machine_id_helpers() {
        // CRC-16/CCITT-FALSE: known vector "123456789" → 0x29B1.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);

        // Base32 of all-zero input → all "A" chars.
        let mut out = [0u8; 20];
        base32_no_il_o01(&[0u8; 12], &mut out, b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789");
        assert_eq!(&out[..], b"AAAAAAAAAAAAAAAAAAAA");

        // Format check on the user's sample: BX1-AFEB-DYKB-YQY4-N7K3-4VAS
        // (28 chars: "BX" + 1 char OS marker + 5 groups of "-XXXX")
        let sample = "BX1-AFEB-DYKB-YQY4-N7K3-4VAS";
        assert_eq!(sample.len(), 28);
        assert!(sample.starts_with("BX"));
        // Skip "BX1-" (the OS marker char + first delimiter).
        let body: Vec<&str> = sample[4..].split('-').collect();
        assert_eq!(body.len(), 5);
        for grp in body {
            assert_eq!(grp.len(), 4);
            for c in grp.chars() {
                assert!(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&(c as u8)));
            }
        }
    }

    #[test]
    fn message_counter_advances() {
        let (mut client, mut server) = make_session_pair();

        // Two messages with the same plaintext must produce different
        // ciphertexts because the message counter changes the per-message
        // nonce.
        let pt = b"same".to_vec();
        let c1 = client.xor_message(Direction::C2sData, pt.clone()).unwrap();
        let c2 = client.xor_message(Direction::C2sData, pt.clone()).unwrap();
        assert_ne!(c1, c2);
        // Server decrypts both in order.
        assert_eq!(server.xor_message(Direction::C2sData, c1).unwrap(), pt);
        assert_eq!(server.xor_message(Direction::C2sData, c2).unwrap(), pt);
    }
}
