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

    let daemonize = Daemonize::new()
        .pid_file("/tmp/test.pid") // Every method except `new` and `start`
        .chown_pid_file(true)      // is optional, see `Daemonize` documentation
        .working_directory("/tmp") // for default behaviour.
        .user("nobody")
        .group("daemon") // Group name
        .group(2)        // or group id.
        .umask(0o777)    // Set umask, `0o027` by default.
        .stdout(stdout)  // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr)  // Redirect stderr to `/tmp/daemon.err`.
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => eprintln!("Error, {}", e),
    }
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
