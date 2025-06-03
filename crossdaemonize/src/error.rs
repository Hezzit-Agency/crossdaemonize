use cfg_if::cfg_if;
use std::fmt;
use std::io;
use std::path::PathBuf;

pub type OsError = i32;

#[derive(Debug)]
pub enum ErrorKind {
    #[cfg(unix)]
    Fork(OsError),
    #[cfg(unix)]
    Wait(OsError),
    #[cfg(unix)]
    DetachSession(OsError),

    GroupNotFound,
    GroupContainsNul,
    SetGroup(OsError),

    UserNotFound,
    UserContainsNul,
    SetUser(OsError),

    ChangeDirectory(OsError),
    PathContainsNul,

    OpenPidfile(OsError),
    #[cfg(unix)]
    GetPidfileFlags(OsError),
    #[cfg(unix)]
    SetPidfileFlags(OsError),
    LockPidfile(OsError),
    #[cfg(unix)]
    ChownPidfile(OsError),

    OpenDeviceNull(OsError),
    RedirectStreams(OsError),
    CloseDeviceNull(OsError),

    TruncatePidfile(OsError),
    WritePid(OsError),
    WritePidUnspecifiedError,
    #[cfg(unix)]
    Chroot(OsError),

    Io(io::Error),
    Custom(String),

    #[cfg(windows)]
    CreateProcessFailed(OsError),
    #[cfg(windows)]
    OpenProcessToken(OsError),
    #[cfg(windows)]
    CreateMutexFailed(OsError),
    #[cfg(windows)]
    ReleaseMutexFailed(OsError),
    #[cfg(windows)]
    SetStdHandleFailed(OsError),
    #[cfg(windows)]
    CreateFileFailed(OsError),
    #[cfg(windows)]
    PrivilegeNotHeld,
    #[cfg(windows)]
    WindowsApiError {
        function_name: String,
        error_code: u32,
    },

    InvalidPath(PathBuf),
    ReadPid(OsError),
}

impl ErrorKind {
    pub fn description(&self) -> String {
        match self {
            #[cfg(unix)]
            ErrorKind::Fork(_) => "unable to fork".to_string(),
            #[cfg(unix)]
            ErrorKind::Wait(_) => "wait failed".to_string(),
            #[cfg(unix)]
            ErrorKind::DetachSession(_) => "unable to create new session".to_string(),
            ErrorKind::GroupNotFound => "unable to resolve group name to group id".to_string(),
            ErrorKind::GroupContainsNul => "group option contains NUL".to_string(),
            ErrorKind::SetGroup(_) => "unable to set group".to_string(),
            ErrorKind::UserNotFound => "unable to resolve user name to user id".to_string(),
            ErrorKind::UserContainsNul => "user option contains NUL".to_string(),
            ErrorKind::SetUser(_) => "unable to set user".to_string(),
            ErrorKind::ChangeDirectory(_) => "unable to change directory".to_string(),
            ErrorKind::PathContainsNul => "path option contains NUL".to_string(),
            ErrorKind::OpenPidfile(_) => "unable to open pid file".to_string(),
            #[cfg(unix)]
            ErrorKind::GetPidfileFlags(_) => "unable get pid file flags".to_string(),
            #[cfg(unix)]
            ErrorKind::SetPidfileFlags(_) => "unable set pid file flags".to_string(),
            ErrorKind::LockPidfile(_) => "unable to lock pid file".to_string(),
            #[cfg(unix)]
            ErrorKind::ChownPidfile(_) => "unable to chown pid file".to_string(),
            ErrorKind::OpenDeviceNull(_) => "unable to open /dev/null or NUL".to_string(),
            ErrorKind::RedirectStreams(_) => "unable to redirect standard streams".to_string(),
            ErrorKind::CloseDeviceNull(_) => "unable to close /dev/null or NUL".to_string(),
            ErrorKind::TruncatePidfile(_) => "unable to truncate pid file".to_string(),
            ErrorKind::WritePid(_) => "unable to write self pid to pid file".to_string(),
            ErrorKind::WritePidUnspecifiedError => {
                "unable to write self pid to pid file due to unknown reason".to_string()
            }
            #[cfg(unix)]
            ErrorKind::Chroot(_) => "unable to chroot into directory".to_string(),

            ErrorKind::Io(e) => format!("I/O error: {}", e),
            ErrorKind::Custom(s) => s.clone(),

            #[cfg(windows)]
            ErrorKind::CreateProcessFailed(_) => "failed to create process".to_string(),
            #[cfg(windows)]
            ErrorKind::OpenProcessToken(_) => "failed to open process token".to_string(),
            #[cfg(windows)]
            ErrorKind::CreateMutexFailed(_) => "failed to create mutex".to_string(),
            #[cfg(windows)]
            ErrorKind::ReleaseMutexFailed(_) => "failed to release mutex".to_string(),
            #[cfg(windows)]
            ErrorKind::SetStdHandleFailed(_) => "failed to set standard handle".to_string(),
            #[cfg(windows)]
            ErrorKind::CreateFileFailed(_) => "failed to create or open file (Windows)".to_string(),
            #[cfg(windows)]
            ErrorKind::PrivilegeNotHeld => "a required privilege is not held".to_string(),
            #[cfg(windows)]
            ErrorKind::WindowsApiError {
                function_name,
                error_code,
            } => {
                format!(
                    "Windows API call '{}' failed with code {}",
                    function_name, error_code
                )
            }

            ErrorKind::InvalidPath(p) => format!("invalid path provided: {:?}", p),
            ErrorKind::ReadPid(_) => "unable to read pid from file".to_string(),
        }
    }

    pub fn get_os_error_code(&self) -> Option<OsError> {
        match self {
            #[cfg(unix)]
            ErrorKind::Fork(e)
            | ErrorKind::Wait(e)
            | ErrorKind::DetachSession(e)
            | ErrorKind::GetPidfileFlags(e)
            | ErrorKind::SetPidfileFlags(e)
            | ErrorKind::ChownPidfile(e)
            | ErrorKind::Chroot(e) => Some(*e),

            ErrorKind::SetGroup(e)
            | ErrorKind::SetUser(e)
            | ErrorKind::ChangeDirectory(e)
            | ErrorKind::OpenPidfile(e)
            | ErrorKind::LockPidfile(e)
            | ErrorKind::OpenDeviceNull(e)
            | ErrorKind::RedirectStreams(e)
            | ErrorKind::CloseDeviceNull(e)
            | ErrorKind::TruncatePidfile(e)
            | ErrorKind::WritePid(e)
            | ErrorKind::ReadPid(e) => Some(*e),

            ErrorKind::Io(io_err) => io_err.raw_os_error(),

            #[cfg(windows)]
            ErrorKind::CreateProcessFailed(e)
            | ErrorKind::OpenProcessToken(e)
            | ErrorKind::CreateMutexFailed(e)
            | ErrorKind::ReleaseMutexFailed(e)
            | ErrorKind::SetStdHandleFailed(e)
            | ErrorKind::CreateFileFailed(e) => Some(*e),

            #[cfg(windows)]
            ErrorKind::WindowsApiError { error_code, .. } => Some(*error_code as OsError),

            #[cfg(windows)]
            ErrorKind::PrivilegeNotHeld => None,

            _ => None,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description())?;
        if let Some(code) = self.get_os_error_code() {
            cfg_if! {
                if #[cfg(windows)] {
                    if !matches!(self, ErrorKind::WindowsApiError { .. } | ErrorKind::Io(_)) {
                        write!(f, " (OS Error Code: {})", code)?;
                    }
                } else {
                    if !matches!(self, ErrorKind::Io(_)) {
                        write!(f, " (OS Error Code: {})", code)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl std::error::Error for ErrorKind {}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error { kind, cause: None }
    }

    #[allow(dead_code)]
    pub fn new_with_cause<E>(kind: ErrorKind, cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Error {
            kind,
            cause: Some(cause.into()),
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Daemonize error: {}", self.kind)?;
        if let Some(ref cause) = self.cause {
            write!(f, "\nCaused by: {}", cause)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|c| &**c as _)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error::new(kind)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::new(ErrorKind::Io(err))
    }
}

#[cfg(unix)]
pub trait Num {
    fn is_err(&self) -> bool;
}

#[cfg(unix)]
macro_rules! impl_num_for_signed_integer {
    ($($t:ty)*) => ($(
        impl Num for $t {
            fn is_err(&self) -> bool {
                *self == -1
            }
        }
    )*)
}

#[cfg(unix)]
impl_num_for_signed_integer!(i8 i16 i32 i64 isize);

#[cfg(unix)]
pub fn get_last_os_error() -> OsError {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(unix)]
pub fn check_err<N: Num, F: FnOnce(OsError) -> ErrorKind>(ret: N, f: F) -> Result<N, ErrorKind> {
    if ret.is_err() {
        Err(f(get_last_os_error()))
    } else {
        Ok(ret)
    }
}

#[cfg(windows)]
pub fn get_last_windows_api_error_kind(function_name: &str) -> ErrorKind {
    let error_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    ErrorKind::WindowsApiError {
        function_name: function_name.to_string(),
        error_code,
    }
}
