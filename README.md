# libcryptsetup-rs

This crate provides Rust bindings for libcryptsetup.

### Sanity testing bindings

There is one test that actually invokes libcryptsetup and can be used for basic sanity
testing of the bindings as it will only succeed if low level bindings are correctly generated,
the high level bindings build, and libcryptsetup successfully encrypts a loopback device.

This can be invoked as follows:

```
sudo cargo test -- --test-threads=1 --ignored
```
