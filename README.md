[![Build Status](https://travis-ci.org/stratis-storage/libcryptsetup-rs.svg?branch=master)](https://travis-ci.org/stratis-storage/libcryptsetup-rs)
[![Latest Version](https://img.shields.io/crates/v/libcryptsetup-rs.svg)](https://crates.io/crates/libcryptsetup-rs)
[![Documentation](https://docs.rs/libcryptsetup-rs/badge.svg)](https://stratis-storage.github.io/libcryptsetup-rs/doc/libcryptsetup_rs/index.html)

# libcryptsetup-rs

This crate provides Rust bindings for libcryptsetup.

### API documentation

The API documentation can be found [here](https://stratis-storage.github.io/libcryptsetup-rs/doc/libcryptsetup_rs/index.html).

### Building

The libcryptsetup bindings require some dependencies outside of cargo to build
properly:
1. cryptsetup (provided by `cryptsetup` on Fedora)
2. cryptsetup development headers (provided by `cryptsetup-devel` on Fedora)
3. libclang (provided by `clang` on Fedora)

### Sanity testing bindings

There is one test that actually invokes libcryptsetup and can be used for basic sanity
testing of the bindings as it will only succeed if low level bindings are correctly generated,
the high level bindings build, and libcryptsetup successfully encrypts a loopback device.

This can be invoked as follows:

```
sudo cargo test -- --test-threads=1 --ignored
```
