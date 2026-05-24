# bobba-xtra

WASM port of the Habbo Origins **BobbaXtra** native Director Xtra
(`BobbaXtra.x32`) for [dirplayer-rs](https://github.com/chameleonxxl/fork-dirplayer),
built against the [`xtra-sdk`](https://github.com/chameleonxxl/dirplayer-rs/tree/main/xtra-sdk)
plugin API.

## What it implements

The same crypto session that the original native Xtra exposes to Lingo:

- Finite-field **Diffie–Hellman** key exchange using the hard-coded
  438-bit prime and generator embedded in `BobbaXtra.x32`
  (sub_10006370 / sub_10006440).
- **HKDF-SHA256** key derivation with salt `"BobbaXtraHKDFSalt"` and
  four per-direction info strings.
- **ChaCha20** (no MAC) for the four directions
  (c2s-data, c2s-header, s2c-data, s2c-header).
- `Device_GetMachineId` — emits an `BX1-XXXX-…` machine id with the
  same shape as the native build, derived from a per-machine random
  seed cached in host `localStorage`.

All four cipher handlers (`Crypto_EncryptPayload`, `Crypto_EncryptHeader`,
`Crypto_DecryptPayload`, `Crypto_DecryptHeader`) wrap the same ChaCha20
pipeline; encrypt does `bytes → XOR → base64-encode`, decrypt does the
reverse.

## Building

```sh
cargo build --target wasm32-unknown-unknown --release
```

The output `.wasm` ends up at
`target/wasm32-unknown-unknown/release/bobba_xtra.wasm`. Point your
dirplayer-rs registry at it (or check it in next to your movie):

```js
// in the host: dev console
setXtraRegistry({ "BobbaXtra.x32": "/bobba_xtra.wasm" });
```

The host's XTRl loader then resolves `BobbaXtra.x32` to that URL
when a movie declares it as a dependency.

## Layout

- `src/lib.rs` — the `XtraPlugin` + `XtraInstance` impls plus
  `xtra_sdk::export_plugin!`. The handler module that was at
  `vm-rust/src/player/xtra/bobba/mod.rs` in the original in-tree port.
- `src/chacha20.rs` / `src/dh.rs` / `src/hkdf.rs` / `src/sha256.rs` —
  the four standalone crypto primitives. No host dependencies; can be
  cargo-tested natively against FIPS / RFC 4231 / RFC 5869 / RFC 7539
  vectors.

## License

GPL-3.0-only.
