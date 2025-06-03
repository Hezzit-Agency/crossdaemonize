// crossdaemonize-tests/examples/tester.rs
extern crate crossdaemonize_tests;

fn main() {
    // This prints the error to stderr if execute_tester_inner() returns Err
    if let Err(e) = crossdaemonize_tests::execute_tester_inner() {
        eprintln!("[TESTER MAIN] Fatal error: {:?}", e);
        std::process::exit(1);
    }
}