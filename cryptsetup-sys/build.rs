extern crate bindgen;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=cryptsetup");

    let bindings = bindgen::Builder::default()
        .header("header.h")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(PathBuf::from("src/"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
