
use cc::Build;

fn main() {
    println!("cargo:rerun-if-changed=src/iface_tap.c");
    Build::new()
        .file("src/iface_tap.c")
        .warnings(true)
        .compile("iface_tap");
}
