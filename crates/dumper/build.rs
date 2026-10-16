use std::path::PathBuf;

fn main() {
    // Read at run time: a compile-time `env!` keeps a stale path after the
    // checkout moves while the cached build-script binary is reused.
    let def_path = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    )
    .join("version.def");

    println!("cargo:rerun-if-changed={}", def_path.to_str().unwrap());
    // The proxy DLL exports must not turn the unit-test executable into a DLL.
    println!(
        "cargo:rustc-link-arg-cdylib=/DEF:{}",
        def_path.to_str().unwrap()
    );
}
