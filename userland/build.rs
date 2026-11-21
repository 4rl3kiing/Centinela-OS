//! Links userland programs at the user image base. `elf-wx` deliberately uses
//! a script with a writable+executable segment: the kernel must refuse it.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    for script in ["link.ld", "link-wx.ld"] {
        println!("cargo:rerun-if-changed={manifest}/{script}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        for (bin, script) in [
            ("elf-hello", "link.ld"),
            ("elf-wx", "link-wx.ld"),
            ("uart-driver", "link.ld"),
            ("kbd-driver", "link.ld"),
            ("serial-service", "link.ld"),
            ("ramfs", "link.ld"),
            ("netsvc", "link.ld"),
            ("shell", "link.ld"),
            ("fs-fuzzer", "link.ld"),
            ("broker", "link.ld"),
            ("badge-client", "link.ld"),
            ("e1000-driver", "link.ld"),
            ("storage", "link.ld"),
            ("storage-client", "link.ld"),
            ("nvme-driver", "link.ld"),
        ] {
            println!("cargo:rustc-link-arg-bin={bin}=-T{manifest}/{script}");
            // Fixed-address static executable (ET_EXEC) from PIC code.
            println!("cargo:rustc-link-arg-bin={bin}=-no-pie");
        }
    }
}
