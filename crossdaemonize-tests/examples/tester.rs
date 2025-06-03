// crossdaemonize-tests/examples/tester.rs
extern crate crossdaemonize_tests;

fn main() {
    // Isso imprimirá o erro para stderr do processo se execute_tester_inner() retornar Err
    if let Err(e) = crossdaemonize_tests::execute_tester_inner() {
        eprintln!("[TESTER MAIN] Fatal error: {:?}", e);
        std::process::exit(1);
    }
}