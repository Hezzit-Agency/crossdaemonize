// crossdaemonize-tests/src/lib.rs

extern crate crossdaemonize;
extern crate tempfile;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use bincode;
use crossdaemonize::{Daemonize, Outcome};

use std::fs::OpenOptions;

#[cfg(unix)]
use libc;

// Public constants used by examples/tester.rs
pub const ARG_PID_FILE: &str = "--pid-file";
pub const ARG_CHOWN_PID_FILE: &str = "--chown-pid-file";
pub const ARG_WORKING_DIRECTORY: &str = "--working-directory"; // absolute path for the working directory
pub const ARG_USER_STRING: &str = "--user-string";
#[cfg(unix)]
pub const ARG_USER_NUM: &str = "--user-num";
pub const ARG_GROUP_STRING: &str = "--group-string";
#[cfg(unix)]
pub const ARG_GROUP_NUM: &str = "--group-num";
pub const ARG_UMASK: &str = "--umask";
pub const ARG_CHROOT: &str = "--chroot";
pub const ARG_STDOUT: &str = "--stdout";
pub const ARG_STDERR: &str = "--stderr";
pub const ARG_ADDITIONAL_FILE: &str = "--additional-file"; // absolute path for the additional file
pub const ARG_SLEEP_MS: &str = "--sleep-ms";
pub const ARG_HUMAN_READABLE: &str = "--human-readable";
pub const ARG_OUTPUT_FILE: &str = "--output-file";

// Public data constants
pub const STDOUT_DATA: &str = "stdout data";
pub const STDERR_DATA: &str = "stderr data";
pub const ADDITIONAL_FILE_DATA: &str = "additional file data";

// Path to the tester executable located in the examples directory
const TESTER_PATH: &str = if cfg!(windows) {
    "../target/debug/examples/tester.exe"
} else {
    "../target/debug/examples/tester"
};

const MAX_WAIT_DURATION: std::time::Duration = std::time::Duration::from_secs(5);

// Tester struct used to configure and run the example daemon
pub struct Tester {
    command: Command,
    _output_file_path: Option<PathBuf>,
}

impl Default for Tester {
    fn default() -> Self {
        Self::new()
    }
}

impl Tester {
    pub fn new() -> Self {
        let command = Command::new(TESTER_PATH);
        Self {
            command,
            _output_file_path: None,
        }
    }

    pub fn pid_file<F: AsRef<Path>>(&mut self, pid_file: F) -> &mut Self {
        self.command.arg(ARG_PID_FILE).arg(pid_file.as_ref());
        self
    }

    pub fn chown_pid_file(&mut self, chown: bool) -> &mut Self {
        self.command.arg(ARG_CHOWN_PID_FILE).arg(chown.to_string());
        self
    }

    pub fn working_directory<F: AsRef<Path>>(&mut self, path: F) -> &mut Self {
        self.command.arg(ARG_WORKING_DIRECTORY).arg(path.as_ref());
        self
    }

    pub fn user_string(&mut self, user: &str) -> &mut Self {
        self.command.arg(ARG_USER_STRING).arg(user);
        self
    }

    #[cfg(unix)]
    pub fn user_num(&mut self, user: u32) -> &mut Self {
        self.command.arg(ARG_USER_NUM).arg(user.to_string());
        self
    }

    pub fn group_string(&mut self, group: &str) -> &mut Self {
        self.command.arg(ARG_GROUP_STRING).arg(group);
        self
    }

    #[cfg(unix)]
    pub fn group_num(&mut self, group: u32) -> &mut Self {
        self.command.arg(ARG_GROUP_NUM).arg(group.to_string());
        self
    }

    pub fn umask(&mut self, umask: u32) -> &mut Self {
        self.command.arg(ARG_UMASK).arg(umask.to_string());
        self
    }

    pub fn chroot<F: AsRef<Path>>(&mut self, path: F) -> &mut Self {
        self.command.arg(ARG_CHROOT).arg(path.as_ref());
        self
    }

    pub fn stdout<F: AsRef<Path>>(&mut self, path: F) -> &mut Self {
        self.command.arg(ARG_STDOUT).arg(path.as_ref());
        self
    }

    pub fn stderr<F: AsRef<Path>>(&mut self, path: F) -> &mut Self {
        self.command.arg(ARG_STDERR).arg(path.as_ref());
        self
    }

    pub fn additional_file<F: AsRef<Path>>(&mut self, path: F) -> &mut Self {
        self.command.arg(ARG_ADDITIONAL_FILE).arg(path.as_ref());
        self
    }

    pub fn sleep(&mut self, duration: std::time::Duration) -> &mut Self {
        self.command
            .arg(ARG_SLEEP_MS)
            .arg(duration.as_millis().to_string());
        self
    }

    // --- Modified run() function ---
    pub fn run(&mut self) -> Result<EnvData, Box<dyn std::error::Error>> {
        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| format!("Failed to create temporary file for output: {}", e))?;
        let output_file_path = temp_file.path().to_path_buf();
        self._output_file_path = Some(output_file_path.clone());

        // Remove the file so the daemonized child can create it with its own permissions
        std::fs::remove_file(&output_file_path).ok();

        self.command.arg(ARG_OUTPUT_FILE).arg(&output_file_path);

        let mut child = self
            .command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("unable to spawn child");

        let st = std::time::Instant::now();

        let exit_status = loop {
            let now = std::time::Instant::now();
            if now - st > MAX_WAIT_DURATION {
                child.kill().ok();
                let mut stderr_output = String::new();
                if let Some(mut stderr_handle) = child.stderr.take() {
                    stderr_handle.read_to_string(&mut stderr_output).ok();
                }
                return Err(format!("timeout waiting for tester result. Stderr: {}", stderr_output).into());
            }
            match child.try_wait().expect("unable to wait for result") {
                Some(result) => break result,
                None => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        };

        let mut stderr_output = String::new();
        if let Some(mut stderr_handle) = child.stderr.take() {
            stderr_handle
                .read_to_string(&mut stderr_output)
                .expect("unable to read tester stderr after child exit");
        }

        if !exit_status.success() {
            return Err(format!(
                "tester exited with status code {:?}, stderr: {}",
                exit_status.code(),
                stderr_output
            ).into());
        }

        let mut data = Vec::new();
        std::fs::File::open(&output_file_path)
            .map_err(|e| format!("Failed to open output file {:?}: {}", output_file_path, e))?
            .read_to_end(&mut data)
            .map_err(|e| format!("Failed to read data from output file {:?}: {}", output_file_path, e))?;

        bincode::deserialize(&data)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

// Data captured from the daemonized process
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvData {
    pub cwd: String,
    pub pid: u32,
    pub euid: u32,
    pub egid: u32,
}

impl EnvData {
    pub fn new() -> EnvData {
        let cwd = std::env::current_dir()
            .expect("unable to get current dir")
            .to_str()
            .expect("invalid path")
            .to_string();

        #[cfg(unix)]
        let (euid, egid) = unsafe { (libc::geteuid() as u32, libc::getegid() as u32) };

        #[cfg(windows)]
        let (euid, egid) = (0, 0);

        Self {
            cwd,
            pid: std::process::id(),
            euid,
            egid,
        }
    }
}

// --- Modified execute_tester_inner() ---
pub fn execute_tester_inner() -> Result<(), Box<dyn std::error::Error>> {
    let log_file_path = "tester_debug.log";
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(log_file_path)
        .map_err(|e| format!("Failed to open log file {}: {}", log_file_path, e))?;

    writeln!(log_file, "[DEBUG - START] Tester started at {:?}", std::time::Instant::now()).ok();
    writeln!(log_file, "[DEBUG - SYSTEM] OS: {}", std::env::consts::OS).ok();
    writeln!(log_file, "[DEBUG - SYSTEM] Parent CWD: {:?}", std::env::current_dir().ok()).ok();

    let mut daemonize_builder = Daemonize::new(); // builder configured using parsed arguments

    #[cfg(windows)]
    {
        daemonize_builder = daemonize_builder.suppress_unsupported_warnings(true);
    }

    let mut args = std::env::args().skip(1);

    fn read_value<T: FromStr>(args: &mut dyn Iterator<Item = String>, key: &str) -> T
    where
        <T as FromStr>::Err: std::fmt::Debug,
    {
        let value = args
            .next()
            .unwrap_or_else(|| panic!("missing value for key {}", key));
        value
            .parse()
            .unwrap_or_else(|_| panic!("invalid value for key {}", key))
    }

    // Variables to store parsed arguments
    let mut pid_file_passed: Option<PathBuf> = None;
    let mut chown_pid_file_passed: Option<bool> = None;
    let mut working_directory_passed: Option<PathBuf> = None;
    let mut user_string_passed: Option<String> = None;
    #[cfg(unix)]
    let mut user_num_passed: Option<u32> = None;
    let mut group_string_passed: Option<String> = None;
    #[cfg(unix)]
    let mut group_num_passed: Option<u32> = None;
    let mut umask_passed: Option<u32> = None;
    let mut chroot_passed: Option<PathBuf> = None;
    let stdout_passed: Option<PathBuf> = None;
    let stderr_passed: Option<PathBuf> = None;
    let mut additional_file_passed: Option<PathBuf> = None;
    let mut sleep_ms_passed: Option<u64> = None;
    let mut human_readable_passed: bool = false;
    let mut output_file_path_parsed: Option<PathBuf> = None;


    writeln!(log_file, "[DEBUG - ARGS] Raw arguments received: {:?}", std::env::args().collect::<Vec<_>>()).ok();

    // Loop to parse all arguments
    while let Some(key) = args.next() {
        writeln!(log_file, "[DEBUG] Processing arg: {}", key).ok();
        daemonize_builder = match key.as_str() {
            ARG_PID_FILE => { pid_file_passed = Some(read_value::<PathBuf>(&mut args, &key)); daemonize_builder }, // Pass the path, configured later
            ARG_CHOWN_PID_FILE => { chown_pid_file_passed = Some(read_value::<bool>(&mut args, &key)); daemonize_builder },
            ARG_WORKING_DIRECTORY => { working_directory_passed = Some(read_value::<PathBuf>(&mut args, &key)); daemonize_builder },
            ARG_USER_STRING => { user_string_passed = Some(read_value::<String>(&mut args, &key)); daemonize_builder },
            #[cfg(unix)]
            ARG_USER_NUM => { user_num_passed = Some(read_value::<u32>(&mut args, &key)); daemonize_builder },
            ARG_GROUP_STRING => { group_string_passed = Some(read_value::<String>(&mut args, &key)); daemonize_builder },
            #[cfg(unix)]
            ARG_GROUP_NUM => { group_num_passed = Some(read_value::<u32>(&mut args, &key)); daemonize_builder },
            ARG_UMASK => { umask_passed = Some(read_value::<u32>(&mut args, &key)); daemonize_builder },
            ARG_CHROOT => { chroot_passed = Some(read_value::<PathBuf>(&mut args, &key)); daemonize_builder },
            ARG_STDOUT => {
                let file_path = read_value::<PathBuf>(&mut args, &key);
                writeln!(log_file, "[DEBUG] Redirecting stdout to: {:?}", file_path).ok();
                let file = std::fs::File::create(&file_path)
                    .map_err(|e| format!("unable to open stdout file {:?}: {}", file_path, e))?;
                daemonize_builder.stdout(file)
            }
            ARG_STDERR => {
                let file_path = read_value::<PathBuf>(&mut args, &key);
                writeln!(log_file, "[DEBUG] Redirecting stderr to: {:?}", file_path).ok();
                let file = std::fs::File::create(&file_path)
                    .map_err(|e| format!("unable to open stderr file {:?}: {}", file_path, e))?;
                daemonize_builder.stderr(file)
            }
            ARG_ADDITIONAL_FILE => { additional_file_passed = Some(read_value::<PathBuf>(&mut args, &key)); daemonize_builder },
            ARG_SLEEP_MS => { sleep_ms_passed = Some(read_value::<u64>(&mut args, &key)); daemonize_builder },
            ARG_HUMAN_READABLE => { human_readable_passed = true; daemonize_builder },
            ARG_OUTPUT_FILE => { output_file_path_parsed = Some(read_value::<PathBuf>(&mut args, &key)); daemonize_builder },
            key => return Err(format!("unknown key: {}", key).into()),
        }
    }

    writeln!(log_file, "[DEBUG] output_file_path_parsed after arg parsing: {:?}", output_file_path_parsed).ok();
    writeln!(log_file, "[DEBUG] working_directory_passed after arg parsing: {:?}", working_directory_passed).ok();
    writeln!(log_file, "[DEBUG] additional_file_passed after arg parsing: {:?}", additional_file_passed).ok();
    writeln!(log_file, "[DEBUG] pid_file_passed after arg parsing: {:?}", pid_file_passed).ok();

    writeln!(
        log_file,
        "[DEBUG] summary - pid_file: {:?}, chown_pid_file: {:?}, working_directory: {:?}, user: {:?}, group: {:?}, umask: {:?}, chroot: {:?}, stdout: {:?}, stderr: {:?}, additional_file: {:?}, sleep_ms: {:?}, human_readable: {}",
        pid_file_passed,
        chown_pid_file_passed,
        working_directory_passed,
        user_string_passed,
        group_string_passed,
        umask_passed,
        chroot_passed,
        stdout_passed,
        stderr_passed,
        additional_file_passed,
        sleep_ms_passed,
        human_readable_passed
    ).ok();

    // Configure the daemonize builder using the parsed arguments

    if let Some(path) = pid_file_passed {
        daemonize_builder = daemonize_builder.pid_file(&path);
    }
    if let Some(b) = chown_pid_file_passed {
        daemonize_builder = daemonize_builder.chown_pid_file(b);
    }
    // working_directory is set on the builder; the directory must exist
    if let Some(path) = working_directory_passed {
        // ensure the directory exists before asking the daemon to switch to it
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("Failed to create working directory {:?} before daemonizing: {}", path, e))?;
        daemonize_builder = daemonize_builder.working_directory(&path);
    }
    if let Some(user) = user_string_passed {
        daemonize_builder = daemonize_builder.user(user.as_str());
    }
    #[cfg(unix)]
    if let Some(user_id) = user_num_passed {
        daemonize_builder = daemonize_builder.user(user_id);
    }
    if let Some(group) = group_string_passed {
        daemonize_builder = daemonize_builder.group(group.as_str());
    }
    #[cfg(unix)]
    if let Some(group_id) = group_num_passed {
        daemonize_builder = daemonize_builder.group(group_id);
    }
    if let Some(umask) = umask_passed {
        daemonize_builder = daemonize_builder.umask(umask);
    }
    if let Some(path) = chroot_passed {
        daemonize_builder = daemonize_builder.chroot(&path);
    }
    // stdout and stderr were configured in the loop if present.
    // additional_file is handled after daemonization in the child.
    // sleep_ms and human_readable are also used only after daemonization.


    let mut dummy_handle = None;
    let (mut read_pipe, write_pipe) = os_pipe::pipe()
        .map_err(|e| format!("unable to open pipe: {}", e))?;


    writeln!(log_file, "[DEBUG] Calling daemonize.execute()").ok();
    match daemonize_builder.execute(&mut dummy_handle) { // Use the configured builder
        Outcome::Parent(_) => {
            writeln!(log_file, "[DEBUG - PARENT] Daemonized process spawned. Exiting parent path.").ok();
            drop(write_pipe);
            read_pipe.read_to_end(&mut Vec::new()).map_err(|e| format!("Parent: unable to read pipe: {}", e))?;
            std::io::stdout().write_all(&[]).map_err(|e| format!("Parent: unable to write data: {}", e))?;
            Ok(())
        }
        Outcome::Child(result) => {
            drop(read_pipe); // close the read end in the child

            writeln!(log_file, "[DEBUG - CHILD] Inside child process. Daemonize result: {:?}", result).ok();

            if let Err(err) = result {
                writeln!(log_file, "[DEBUG - CHILD - ERROR] Daemonize failed: {:?}", err).ok();
                return Err(Box::new(err));
            }

            // handle additional_file in the child; the directory was created by the parent
            if let Some(path) = additional_file_passed {
                writeln!(log_file, "[DEBUG - CHILD] Creating additional file: {:?}", path).ok();
                if let Ok(mut file) = std::fs::File::create(&path) {
                    file.write_all(ADDITIONAL_FILE_DATA.as_bytes()).ok();
                } else {
                    let create_err = std::io::Error::last_os_error();
                    writeln!(log_file, "[DEBUG - CHILD - ERROR] Failed to create additional file {:?}: {}. OS Error: {}", path, create_err, create_err.raw_os_error().unwrap_or(0)).ok();
                }
            }


            writeln!(log_file, "[DEBUG - CHILD] Daemonize successful. Creating EnvData.").ok();
            let env = EnvData::new();
            writeln!(log_file, "[DEBUG - CHILD] EnvData created: {:?}", env).ok();
            print!("{}", STDOUT_DATA);
            eprint!("{}", STDERR_DATA);

            if let Some(path) = output_file_path_parsed {
                writeln!(log_file, "[DEBUG - CHILD] Writing EnvData to temporary file: {:?}", path).ok();
                let mut output_file = std::fs::File::create(&path)
                    .map_err(|e| format!("Child: Failed to create output file {:?}: {}", path, e))?;

                if human_readable_passed {
                    writeln!(log_file, "[DEBUG - CHILD] Serializing human readable EnvData to file.").ok();
                    output_file.write_all(format!("{:?}\n", env).as_bytes())
                        .map_err(|e| format!("Child: failed to write human readable data to file: {}", e))?;
                } else {
                    writeln!(log_file, "[DEBUG - CHILD] Serializing bincode EnvData to file.").ok();
                    let data = bincode::serialize(&env)
                        .map_err(|e| format!("Child: bincode serialization failed to file: {}", e))?;
                    output_file.write_all(&data)
                        .map_err(|e| format!("Child: failed to write bincode data to file: {}", e))?;
                }
                output_file.flush()
                    .map_err(|e| format!("Child: failed to flush output file: {}", e))?;
                writeln!(log_file, "[DEBUG - CHILD] Data written to temporary file. Closing file.").ok();

            } else {
                writeln!(log_file, "[DEBUG - CHILD - ERROR] Output file path not provided! This is an error in test setup.").ok();
                return Err("Output file path not provided to tester.".into());
            }

            writeln!(log_file, "[DEBUG - CHILD] Dropping main write_pipe (not used for EnvData).").ok();
            drop(write_pipe);

            if let Some(duration_ms) = sleep_ms_passed {
                writeln!(log_file, "[DEBUG - CHILD] Sleeping for {}ms.", duration_ms).ok();
                std::thread::sleep(std::time::Duration::from_millis(duration_ms));
            }
            writeln!(log_file, "[DEBUG - CHILD] Child process finished successfully.").ok();
            Ok(())
        }
    }
}

// Compatibility wrapper that calls execute_tester_inner
pub fn execute_tester() {
    if let Err(e) = execute_tester_inner() {
        eprintln!("[FACADE] Error in execute_tester: {:?}", e);
        std::process::exit(1);
    }
}