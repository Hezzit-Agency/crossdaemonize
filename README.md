# crossdaemonize [![Latest Version](https://img.shields.io/crates/v/crossdaemonize.svg)](https://crates.io/crates/crossdaemonize) [![docs](https://docs.rs/crossdaemonize/badge.svg)](https://docs.rs/crossdaemonize)

`crossdaemonize` is a cross-platform library for turning a process into a background service. It builds on the original [daemonize](https://github.com/knsd/daemonize) crate by Fedor Gogolev and extends its capabilities with native Windows support.

## Features
* Launch a process as a daemon on Unix or Windows
* Optional PID file management
* Configure working directory and stream redirection
* Unix-only options for user, group, umask and chroot
* Suppression of unsupported warnings on Windows

## Example (Unix)
```rust
use std::fs::File;
use crossdaemonize::Daemonize;

fn main() {
    let stdout = File::create("/tmp/daemon.out").unwrap();
    let stderr = File::create("/tmp/daemon.err").unwrap();

    Daemonize::new()
        .pid_file("/tmp/test.pid")
        .working_directory("/tmp")
        .stdout(stdout)
        .stderr(stderr)
        .start()
        .expect("daemonize failed");
}
```

## Example (Windows)
```rust
use std::fs::File;
use crossdaemonize::Daemonize;

fn main() {
    let stdout = File::create("C:\\daemon.out").unwrap();
    let stderr = File::create("C:\\daemon.err").unwrap();

    Daemonize::new()
        .pid_file("C:\\daemon.pid")
        .working_directory("C:\\")
        .stdout(stdout)
        .stderr(stderr)
        .suppress_unsupported_warnings(true)
        .start()
        .expect("daemonize failed");
}
```

## License
Licensed under either of
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))
at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
