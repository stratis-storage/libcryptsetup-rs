use pkg_config::{Config, Library};
use semver::Version;
use std::env;
use std::path::PathBuf;

fn get_library() -> Library {
    match Config::new()
        .atleast_version("2.2.0")
        .probe("libcryptsetup")
    {
        Ok(l) => l,
        Err(e) => panic!("Bindings require at least cryptsetup-2.2.0: {e}"),
    }
}

fn get_version(l: &Library) -> Version {
    Version::parse(&l.version).expect("Could not parse version")
}

fn safe_free_is_needed(l: &Library) -> bool {
    let version = get_version(l);
    version < Version::new(2, 3, 0)
}

fn build_safe_free() {
    cc::Build::new().file("safe_free.c").compile("safe_free");
    println!("cargo:rustc-link-lib=cryptsetup");
}

fn generate_bindings(l: Library, safe_free_is_needed: bool) {
    let builder = bindgen::Builder::default()
        .clang_args(
            l.include_paths
                .iter()
                .map(|path| format!("-I{}", path.to_string_lossy())),
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
    let l = get_library();
    let safe_free_is_needed = safe_free_is_needed(&l);
    if safe_free_is_needed {
        build_safe_free();
    }
    generate_bindings(l, safe_free_is_needed);
    println!("cargo:rerun-if-changed=header.h");
}
