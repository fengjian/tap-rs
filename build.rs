
use cc::Build;

fn main() {
    Build::new()
        .file("src/iface_tap.c")
        .warnings(true)
        .compile("iface_tap");
}
