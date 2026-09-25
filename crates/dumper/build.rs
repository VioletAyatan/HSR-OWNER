use std::path::PathBuf;

fn main() {
    let def_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("version.def");

    println!("cargo:rerun-if-changed={}", def_path.to_str().unwrap());
    // The proxy DLL exports must not turn the unit-test executable into a DLL.
    println!(
        "cargo:rustc-link-arg-cdylib=/DEF:{}",
        def_path.to_str().unwrap()
    );
}
