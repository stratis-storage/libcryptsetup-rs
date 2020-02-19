use std::env;

use bindgen;
use cc;
use pkg_config::Config;

use std::path::PathBuf;

fn safe_free_is_needed() -> bool {
    match Config::new().atleast_version("2.3.0").probe("libcryptsetup") {
        Ok(_) => false,
        Err(_) => {
            match Config::new().atleast_version("2.2.0").probe("libcryptsetup") {
                Ok(_) => true,
                Err(e) => panic!("Bindings require at least cryptsetup-2.2: {}", e),
            }
        }
    }
}

fn build_safe_free() {
    println!("cargo:rustc-link-lib=cryptsetup");

    cc::Build::new().file("safe_free.c").compile("safe_free");
}

fn generate_bindings(safe_free_is_needed: bool) {
    let mut builder = bindgen::Builder::default().header("header.h").size_t_is_usize(true);
    if safe_free_is_needed {
        builder = builder.header("safe_free.h");
    }
    let bindings = builder.generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}

fn main() {
    let safe_free_is_needed = safe_free_is_needed();
    if safe_free_is_needed {
        build_safe_free();
    }
    generate_bindings(safe_free_is_needed);
}
