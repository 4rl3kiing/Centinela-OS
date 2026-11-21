//! Links userland programs at the user image base. `elf-wx` deliberately uses
//! a script with a writable+executable segment: the kernel must refuse it.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    for script in ["link.ld", "link-wx.ld"] {
        println!("cargo:rerun-if-changed={manifest}/{script}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-arg-bin=elf-hello=-T{manifest}/link.ld");
        println!("cargo:rustc-link-arg-bin=elf-wx=-T{manifest}/link-wx.ld");
    }
}
