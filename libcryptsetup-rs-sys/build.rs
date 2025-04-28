use std::env;

use pkg_config::{Config, Library};
use semver::Version;

use std::path::PathBuf;

fn probe() -> Library {
    let mut config = Config::new();
    #[cfg(feature = "static")]
    config.statik(true);
    match config.atleast_version("2.2.0").probe("libcryptsetup") {
        Ok(l) => l,
        Err(e) => panic!("Bindings require at least cryptsetup-2.2.0: {e}"),
    }
}

fn build_safe_free() {
    cc::Build::new().file("safe_free.c").compile("safe_free");

    println!("cargo:rustc-link-lib=cryptsetup");
}

fn generate_bindings(library: &Library, safe_free_is_needed: bool) {
    let builder = bindgen::Builder::default()
        .rust_target(bindgen::RustTarget::Stable_1_73)
        .clang_args(
            library
                .include_paths
                .iter()
                .map(|path| format!("-I{}", path.display())),
        )
        .header("header.h")
        .size_t_is_usize(true);
    #[cfg(target_arch = "x86")]
    let builder = builder.blocklist_type("max_align_t");
    let builder_with_safe_free = if safe_free_is_needed {
        builder.header("safe_free.h")
    } else {
        builder
    };
    let bindings = builder_with_safe_free
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}

fn main() {
    let library = probe();
    let version = Version::parse(&library.version).expect("Could not parse version");
    let safe_free_is_needed = version < Version::new(2, 3, 0);
    if safe_free_is_needed {
        build_safe_free();
    }
    generate_bindings(&library, safe_free_is_needed);
    println!("cargo:rerun-if-changed=header.h");
}
