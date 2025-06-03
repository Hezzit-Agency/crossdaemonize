# Collaboration Guidelines

Follow these rules whenever you modify this repository:

1. **Code Format**
   Run `cargo fmt --all` before committing to keep a consistent code style.

2. **Tests**
   Execute `./run_tests.sh` and make sure all tests pass.
   The merge will only be performed if the tests finish without warnings or errors.

3. **Generated Files**
   Do not commit automatically generated files such as
   `crossdaemonize-tests/tester_debug.log` or `test_output.log`.

4. **Language**
   Keep variable names, function names and comments in English.

5. **Version and Changelog**
   Do not change the package version or `CHANGELOG.md`. Those updates
   will be added later by the maintainer once the merge is approved.

Always follow these instructions when working on any part of the project.
