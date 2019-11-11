extern crate bindgen;
extern crate cc;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=cryptsetup");

    cc::Build::new()
        .file("safe_free.c")
        .compile("safe_free");

    let bindings = bindgen::Builder::default()
        .header("header.h")
        .header("safe_free.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from("src/bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings");
}
