//! Links the kernel binary with its own linker script (userland binaries in
//! the same workspace use a different one).
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let script = format!("{manifest}/../linker/x86_64.ld");
    println!("cargo:rerun-if-changed={script}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-arg-bin=centinela-kernel=-T{script}");
    }
}
