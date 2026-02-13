fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let version_script = format!("{manifest_dir}/version_scripts/libc.map");
    let debug_assertions_enabled = std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some();
    if !debug_assertions_enabled && std::path::Path::new(&version_script).exists() {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={version_script}");
    }
    println!("cargo:rerun-if-changed=version_scripts/libc.map");
}
