fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let version_script = format!("{manifest_dir}/version_scripts/libc.map");
    if std::path::Path::new(&version_script).exists() {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={version_script}");
    }
    println!("cargo:rerun-if-changed=version_scripts/libc.map");
}
