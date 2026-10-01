// Tauri needs to know whether to run its codegen, and it is only meaningful
// when the `gui` feature is on. Without this check, `cargo test` (no
// features) would still invoke tauri-build, which generates the context and
// requires a `tauri.conf.json` and the GUI toolchain — reintroducing exactly
// the dependency the feature was added to remove.
//
// The `#[cfg]` matters as well as the env var: `tauri-build` is an *optional*
// dependency, so with the feature off the crate is not linked and even an
// unreachable reference fails to resolve.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_GUI");
    #[cfg(feature = "gui")]
    tauri_build::build();
}
