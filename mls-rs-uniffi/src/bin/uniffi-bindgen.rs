// Bindgen binary alias for the mls-rs-uniffi package.
//
// The "real" bindgen binary lives in the sibling `uniffi-bindgen` workspace
// member, but maturin's UniFFI integration runs `cargo run --bin uniffi-bindgen`
// scoped to the package being built (mls-rs-uniffi). When that package has no
// such binary, the build fails with "no bin target named `uniffi-bindgen` in
// default-run packages." Adding this thin alias here lets maturin find a
// `uniffi-bindgen` target inside mls-rs-uniffi itself, gated behind the
// `uniffi-bindgen-binary` feature so library builds don't pull in clap.
fn main() {
    uniffi::uniffi_bindgen_main()
}
