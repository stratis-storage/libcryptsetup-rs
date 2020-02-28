use pkg_config::Config;
use semver::Version;

static SUPPORTED_VERSIONS: &[&'static str] = &[
    "2.2.0",
    "2.3.0",
];

fn main() {
    let version = match Config::new().atleast_version("2.2.0").probe("libcryptsetup") {
        Ok(l) => Version::parse(&l.version).expect("Could not parse version"),
        Err(e) => panic!("Bindings require at least cryptsetup-2.2.0: {}", e),
    };
    for ver in SUPPORTED_VERSIONS.iter().take_while(|ver_string| {
        let iter_version = Version::parse(ver_string).unwrap();
        version >= iter_version
    }) {
        println!(
            "cargo:rustc-cfg=cryptsetup{}supported",
            ver.split('.').take(2).fold(String::new(), |mut acc, next| {
                acc.push_str(next);
                acc
            })
        );
    }
}
