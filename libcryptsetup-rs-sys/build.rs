use std::env;

use bindgen;
use cc;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=cryptsetup");

    cc::Build::new().file("safe_free.c").compile("safe_free");

    let bindings = bindgen::Builder::default()
        .header("header.h")
        .header("safe_free.h")
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
