# crossdaemonize [![Latest Version](https://img.shields.io/crates/v/crossdaemonize.svg)](https://crates.io/crates/crossdaemonize) [![docs](https://docs.rs/crossdaemonize/badge.svg)](https://docs.rs/crossdaemonize)

`crossdaemonize` is a cross-platform library for turning a process into a background service. It builds on the original [daemonize](https://github.com/knsd/daemonize) crate by Fedor Gogolev and extends its capabilities with native Windows support.

## Features
* Launch a process as a daemon on Unix or Windows
* Optional PID file management
* Configure working directory and stream redirection
* Unix-only options for user, group, umask and chroot
* Suppression of unsupported warnings on Windows

## Example
```rust
use std::fs::File;
use crossdaemonize::Daemonize;
use tempfile::tempdir;

fn main() {
    let tmp = tempdir().expect("failed to create temporary directory");
    let stdout = File::create(tmp.path().join("daemon.out")).unwrap();
    let stderr = File::create(tmp.path().join("daemon.err")).unwrap();
    let pid_file = tmp.path().join("daemon.pid");

    let daemonize = Daemonize::new()
        .pid_file(&pid_file)
        .working_directory(tmp.path())
        .stdout(stdout)
        .stderr(stderr);

    #[cfg(unix)]
    let daemonize = daemonize
        .user("nobody")
        .group("daemon")
        .umask(0o777)
        .privileged_action(|| "Executed before drop privileges");

    daemonize
        .start()
        .expect("daemonize failed");
}
```

## Windows Limitations
On Windows the library cannot change user, group, umask or perform `chroot`.
These methods are ignored unless `suppress_unsupported_warnings(false)` is used (default).

## License
Licensed under either of
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))
at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
