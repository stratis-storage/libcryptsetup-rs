# libcryptsetup-rs

This crate provides Rust bindings for libcryptsetup.

### Sanity testing bindings

There is one test that actually invokes libcryptsetup and can be used for basic sanity
testing of the bindings as it will only succeed if low level bindings are correctly generated,
the high level bindings build, and libcryptsetup successfully encrypts a loopback device.

This can be invoked as follows:

```
sudo cargo test <TEST_NAME> -- --test-threads=1 --ignored
```

Tests should only ever be run one at a time so a test name matching exactly
one test is required. Otherwise, you may see spurious failures.
