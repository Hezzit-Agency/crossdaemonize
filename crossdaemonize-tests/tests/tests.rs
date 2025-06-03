// crossdaemonize-tests/tests/tests.rs

extern crate crossdaemonize_tests;
extern crate tempfile;

use crossdaemonize_tests::{Tester, STDOUT_DATA, STDERR_DATA};
#[cfg(windows)]
use crossdaemonize_tests::ADDITIONAL_FILE_DATA;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use tempfile::TempDir;

#[test]
fn simple() {
    let result = Tester::new().run();
    assert!(result.is_ok(), "Simple test failed: {:?}", result.unwrap_err());
}

#[test]
fn chdir() {
    let _result_init = Tester::new().run().unwrap();

    // --- create temporary directory and pass full path ---
    let temp_dir_for_chdir = TempDir::new().expect("Failed to create temp dir for chdir test");
    let target_dir_path = temp_dir_for_chdir.path().to_path_buf(); // full path of the temporary directory

    let _result_chdir = Tester::new().working_directory(&target_dir_path).run();
    assert!(_result_chdir.is_ok(), "chdir test failed: {:?}", _result_chdir.unwrap_err());

    #[cfg(unix)]
    {
        let expected_cwd = temp_dir_for_chdir.path().canonicalize()
            .expect("Failed to canonicalize path for chdir test")
            .to_string_lossy()
            .to_string();
        let actual_cwd = _result_chdir.unwrap().cwd;
        assert_eq!(actual_cwd, expected_cwd, "CWD should match the temporary directory on Unix");
    }
    #[cfg(windows)]
    {
        // Canonicalize para resolver ., .. e garantir o formato completo.
        let expected_cwd = temp_dir_for_chdir.path().canonicalize() // O processo filho deve ter mudado para este dir
                                .expect("Failed to canonicalize path for chdir test")
                                .to_string_lossy()
                                .to_string();
        let expected_cwd = expected_cwd.trim_end_matches('\\').trim_end_matches('/').to_string();
        let actual_cwd = _result_chdir.unwrap().cwd.trim_end_matches('\\').trim_end_matches('/').to_string();

        assert_eq!(actual_cwd, expected_cwd, "CWD should match the temporary directory on Windows");
    }
}

#[test]
fn umask() {
    // --- CRIAÇÃO DO DIRETÓRIO TEMPORÁRIO PELO PAI PARA O ARQUIVO ADICIONAL ---
    let tmpdir_for_additional_file = TempDir::new().expect("Failed to create tmpdir for additional file");
    let path = tmpdir_for_additional_file.path().join("umask-test-file"); // Caminho completo para o arquivo

    let _result_umask = Tester::new().umask(0o222).additional_file(&path).run();
    assert!(_result_umask.is_ok(), "Umask test failed: {:?}", _result_umask.unwrap_err());

    // Se o teste passou, o arquivo adicional deveria ter sido criado neste caminho.
    #[cfg(unix)]
    {
        assert!(path.metadata().unwrap().permissions().readonly());
    }
    #[cfg(windows)]
    {
        assert!(path.exists(), "Additional file should exist on Windows.");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ADDITIONAL_FILE_DATA, "Additional file content should match.");
    }
}

#[test]
fn pid() {
    // --- CRIAÇÃO DO DIRETÓRIO TEMPORÁRIO PELO PAI PARA O PID FILE ---
    let tmpdir_for_pid = TempDir::new().expect("Failed to create tmpdir for pid file");
    let path = tmpdir_for_pid.path().join("pid"); // Caminho completo para o PID file

    // Primeira execução: deve criar o pidfile
    let _result_first_run = Tester::new()
        .pid_file(&path) // Passa o caminho completo
        .sleep(std::time::Duration::from_secs(1))
        .run();
    assert!(_result_first_run.is_ok(), "First PID run should succeed: {:?}", _result_first_run.unwrap_err());
    let pid_content = std::fs::read_to_string(&path).expect("Should read pid file");
    assert!(pid_content.ends_with('\n'), "PID content should end with newline");
    let pid = pid_content[..pid_content.len() - 1].parse().expect("PID should be parsable");
    assert_eq!(_result_first_run.unwrap().pid, pid, "PID from EnvData should match PID in file");

    // Segunda execução: deve falhar ao criar o pidfile existente (se o lock funcionar)
    let _result_second_run = Tester::new().pid_file(&path).run(); // Passa o caminho completo
    assert!(_result_second_run.is_err(), "Second PID run should fail because pidfile exists/is locked");
}

#[test]
fn redirect_stream() {
    let tmpdir = TempDir::new().unwrap(); // Created here for all operations
    let stdout = tmpdir.path().join("stdout");
    let stderr = tmpdir.path().join("stderr");

    // Teste 1: stdout e stderr redirecionados
    let _result1 = Tester::new().stdout(&stdout).stderr(&stderr).run();
    assert!(_result1.is_ok(), "Redirect stream test 1 failed: {:?}", _result1.unwrap_err());

    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);

    std::fs::remove_file(&stdout).unwrap();
    std::fs::remove_file(&stderr).unwrap();

    // Teste 2: apenas stdout redirecionado
    let _result2 = Tester::new().stdout(&stdout).run();
    assert!(_result2.is_ok(), "Redirect stream test 2 failed: {:?}", _result2.unwrap_err());
    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(
        std::fs::metadata(&stderr).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::remove_file(&stdout).unwrap();

    // Teste 3: apenas stderr redirecionado
    let _result3 = Tester::new().stderr(&stderr).run();
    assert!(_result3.is_ok(), "Redirect stream test 3 failed: {:?}", _result3.unwrap_err());
    assert_eq!(
        std::fs::metadata(&stdout).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);
}
#[test]
fn complex_run() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let workdir = tmpdir.path().join("wd");
    std::fs::create_dir_all(&workdir).unwrap();
    let stdout = tmpdir.path().join("stdout");
    let stderr = tmpdir.path().join("stderr");
    let pid = tmpdir.path().join("pidfile");
    let additional = tmpdir.path().join("extra");

    let result = Tester::new()
        .working_directory(&workdir)
        .stdout(&stdout)
        .stderr(&stderr)
        .pid_file(&pid)
        .additional_file(&additional)
        .sleep(std::time::Duration::from_millis(100))
        .run();

    assert!(result.is_ok(), "Complex run failed: {:?}", result.unwrap_err());
    assert!(stdout.exists());
    assert!(stderr.exists());
    assert!(pid.exists());
    assert!(additional.exists());
}

#[cfg(unix)]
#[test]
fn user_group_string() {
    let result = Tester::new()
        .user_string("nobody")
        .group_string("daemon")
        .run();
    assert!(result.is_ok(), "user/group string test failed: {:?}", result.unwrap_err());
    let env = result.unwrap();
    assert_eq!(env.euid, 65534, "euid should drop to nobody");
    assert_eq!(env.egid, 1, "egid should drop to daemon group");
}

#[cfg(unix)]
#[test]
fn user_group_numeric() {
    let result = Tester::new()
        .user_num(65534)
        .group_num(1)
        .run();
    assert!(result.is_ok(), "user/group numeric test failed: {:?}", result.unwrap_err());
    let env = result.unwrap();
    assert_eq!(env.euid, 65534);
    assert_eq!(env.egid, 1);
}

#[test]
fn chown_pid_file() {
    let tmpdir = TempDir::new().expect("Failed to create tmpdir for chown pid");
    let pid_path = tmpdir.path().join("pidfile");

    let result = Tester::new()
        .pid_file(&pid_path)
        .chown_pid_file(true)
        .user_string("nobody")
        .group_string("daemon")
        .run();
    assert!(result.is_ok(), "chown pidfile test failed: {:?}", result.unwrap_err());

    #[cfg(unix)]
    {
        use std::fs::metadata;
        let meta = metadata(&pid_path).unwrap();
        assert_eq!(meta.uid(), 65534, "pid file uid should be nobody");
        assert_eq!(meta.gid(), 1, "pid file gid should be daemon");
    }
}

