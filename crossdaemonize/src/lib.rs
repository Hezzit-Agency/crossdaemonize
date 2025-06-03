// Copyright (c) 2016 Fedor Gogolev <knsd@knsd.net>
// Modificado para tentativa de porte para Windows.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//!
//! daemonize is a library for writing system daemons/background processes.
//! This version attempts to add Windows compatibility.
//!
//! The original repository is located at <https://github.com/knsd/daemonize/>.
//!
//! # Windows Specifics:
//!
//! On Windows, daemonization is achieved by relaunching the current executable
//! as a detached process without a console window. The original process then exits.
//!
//! ## Ignored Features on Windows:
//!
//! Due to fundamental differences in operating system design, the following
//! `Daemonize` configurations are **ignored** when targeting Windows:
//!
//! * `chown_pid_file`: Windows uses ACLs for file permissions, not Unix-style ownership.
//! * `user` and `group`: Windows manages process identity via user accounts and services,
//!     not simple UID/GID changes. To run a process under a different user, consider
//!     creating a Windows Service.
//! * `umask`: Windows uses ACLs for default file permissions, not a umask.
//! * `chroot`: The concept of changing the root directory does not apply to Windows.
//!
//! Warnings for these ignored features can be suppressed using `.suppress_unsupported_warnings(true)`.
//!

// Adicione esta linha no topo do seu lib.rs ou main.rs para desativar o aviso em todo o crate
// #![allow(clippy::collapsible_match)]
// Ou para funções específicas, se preferir:
// #[allow(clippy::collapsible_match)]

mod error;

extern crate cfg_if;

use cfg_if::cfg_if;
use std::path::{Path, PathBuf};
use std::fmt;
use std::fs::File;
use std::process::exit;

cfg_if! {
    if #[cfg(unix)] {
        extern crate libc;
        use std::os::unix::ffi::{OsStringExt, OsStrExt};
        use std::os::unix::io::{AsRawFd, RawFd};
        use std::env::set_current_dir;
        use std::ffi::CString;
    } else if #[cfg(windows)] {
        extern crate windows_sys;
        use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, HWND};
        use windows_sys::Win32::System::Threading::{
            CreateMutexW, ReleaseMutex, WaitForSingleObject, GetCurrentProcessId,
            CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, DETACHED_PROCESS, CREATE_NO_WINDOW
        };
        use windows_sys::Win32::System::Console::{
            SetStdHandle, GetConsoleWindow,
            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
        };
        use windows_sys::Win32::System::Environment::SetCurrentDirectoryW;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, WriteFile, FlushFileBuffers,
            OPEN_EXISTING, CREATE_NEW, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL,
            TRUNCATE_EXISTING, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_WRITE,
            CREATE_ALWAYS 
        };
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;

        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::IntoRawHandle;
        use std::ptr;
        const WAIT_OBJECT_0: u32 = 0x00000000_u32;
        const WAIT_ABANDONED: u32 = 0x00000080_u32;
        const WAIT_TIMEOUT: u32 = 0x00000102_u32;
    }
}

use self::error::ErrorKind;
pub use self::error::Error;

cfg_if! {
    if #[cfg(windows)] {
        type MutexHandle = HANDLE;
    } else {
        type MutexHandle = ();
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum UserImpl {
    Name(String),
    #[cfg(unix)]
    Id(libc::uid_t),
    #[cfg(windows)]
    #[allow(dead_code)] // Allow because this variant is not constructed on Windows yet
    Id(String), // No Windows, UIDs são SIDs, String é uma simplificação
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct User {
    inner: UserImpl,
}

impl From<&str> for User {
    fn from(t: &str) -> User {
        User {
            inner: UserImpl::Name(t.to_owned()),
        }
    }
}

cfg_if! {
    if #[cfg(unix)] {
        impl From<u32> for User {
            fn from(t: u32) -> User {
                User {
                    inner: UserImpl::Id(t as libc::uid_t),
                }
            }
        }
    }
    // Nota: From<u32> para User não é implementado para Windows,
    // já que IDs de usuário não são simples u32.
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupImpl {
    Name(String),
    #[cfg(unix)]
    Id(libc::gid_t),
    #[cfg(windows)]
    #[allow(dead_code)] // Allow because this variant is not constructed on Windows yet
    Id(String), // No Windows, GIDs são SIDs, String é uma simplificação
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Group {
    inner: GroupImpl,
}

impl From<&str> for Group {
    fn from(t: &str) -> Group {
        Group {
            inner: GroupImpl::Name(t.to_owned()),
        }
    }
}

cfg_if! {
    if #[cfg(unix)] {
        impl From<u32> for Group {
            fn from(t: u32) -> Group {
                Group {
                    inner: GroupImpl::Id(t as libc::gid_t),
                }
            }
        }
    }
    // Nota: From<u32> para Group não é implementado para Windows.
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mask {
    #[cfg(unix)]
    inner: libc::mode_t,
    #[cfg(windows)]
    inner: u32, // umask não tem análogo direto no Windows; este campo pode ser ignorado.
}

impl From<u32> for Mask {
    fn from(inner_val: u32) -> Mask {
        Mask {
            #[cfg(unix)]
            inner: inner_val as libc::mode_t,
            #[cfg(windows)]
            inner: inner_val, // No Windows, este valor não é usado diretamente como umask.
        }
    }
}

#[derive(Debug)]
enum StdioImpl {
    Devnull,
    RedirectToFile(File), // File não é Copy, então o match precisa ter cuidado
    Keep,
}

#[derive(Debug)]
pub struct Stdio {
    inner: StdioImpl,
}

impl Stdio {
    pub fn devnull() -> Self {
        Self {
            inner: StdioImpl::Devnull,
        }
    }

    pub fn keep() -> Self {
        Self {
            inner: StdioImpl::Keep,
        }
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Self {
        Self {
            inner: StdioImpl::RedirectToFile(file),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Parent {
    #[cfg(unix)]
    pub first_child_exit_code: i32,
    #[cfg(windows)]
    pub child_process_id: Option<u32>, // ID do processo filho desanexado
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Child<T> {
    pub privileged_action_result: T,
}

#[derive(Debug)]
pub enum Outcome<T> {
    Parent(Result<Parent, Error>),
    Child(Result<Child<T>, Error>),
}

impl<T> Outcome<T> {
    pub fn is_parent(&self) -> bool {
        matches!(self, Outcome::Parent(_))
    }

    pub fn is_child(&self) -> bool {
        matches!(self, Outcome::Child(_))
    }
}

pub struct Daemonize<T> {
    directory: PathBuf,
    pid_file: Option<PathBuf>,
    chown_pid_file: bool, // Ignorado no Windows
    user: Option<User>,    // Ignorado no Windows (requer APIs de serviço ou tokens de processo)
    group: Option<Group>,    // Ignorado no Windows
    umask: Mask,             // Ignorado no Windows
    root: Option<PathBuf>,  // Ignorado no Windows (chroot não aplicável)
    privileged_action: Box<dyn FnOnce() -> T>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    #[cfg(windows)]
    suppress_unsupported_warnings: bool, // Novo campo para controlar avisos no Windows
}

impl<T> fmt::Debug for Daemonize<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = fmt.debug_struct("Daemonize");
        debug_struct
            .field("directory", &self.directory)
            .field("pid_file", &self.pid_file)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr);

        cfg_if! {
            if #[cfg(unix)] {
                debug_struct
                    .field("chown_pid_file", &self.chown_pid_file)
                    .field("user", &self.user)
                    .field("group", &self.group)
                    .field("umask", &self.umask)
                    .field("root", &self.root);
            } else {
                // No Windows, alguns campos são ignorados, mas podemos listá-los para completude
                 debug_struct
                    .field("chown_pid_file (ignored on Windows)", &self.chown_pid_file)
                    .field("user (ignored on Windows)", &self.user)
                    .field("group (ignored on Windows)", &self.group)
                    .field("umask (ignored on Windows)", &self.umask)
                    .field("root (ignored on Windows)", &self.root)
                    .field("suppress_unsupported_warnings", &self.suppress_unsupported_warnings); // Incluir o novo campo
            }
        }
        debug_struct.finish()
    }
}

impl Default for Daemonize<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemonize<()> {
    pub fn new() -> Self {
        let default_path_str: &str = if cfg!(unix) { "/" } else { "." }; // Diretório atual para Windows
        Daemonize {
            directory: PathBuf::from(default_path_str),
            pid_file: None,
            chown_pid_file: false,
            user: None,
            group: None,
            umask: 0o027.into(), // Padrão Unix, ignorado no Windows
            privileged_action: Box::new(|| ()),
            root: None,
            stdin: Stdio::devnull(),
            stdout: Stdio::devnull(),
            stderr: Stdio::devnull(),
            #[cfg(windows)]
            suppress_unsupported_warnings: false, // Padrão é mostrar avisos
        }
    }
}

impl<T> Daemonize<T> {
    pub fn pid_file<F: AsRef<Path>>(mut self, path: F) -> Self {
        self.pid_file = Some(path.as_ref().to_owned());
        self
    }

    #[allow(unused_mut)] // Suppress warning on Windows where 'self' isn't explicitly reassigned
    pub fn chown_pid_file(mut self, chown: bool) -> Self {
        cfg_if! {
            if #[cfg(unix)] {
                self.chown_pid_file = chown;
            } else {
                let _ = chown; // Evita warning de não utilizado
                if !self.suppress_unsupported_warnings {
                    eprintln!("Warning: chown_pid_file is not supported on Windows and will be ignored.");
                }
            }
        }
        self
    }

    pub fn working_directory<F: AsRef<Path>>(mut self, path: F) -> Self {
        self.directory = path.as_ref().to_owned();
        self
    }

    #[allow(unused_mut)] // Suppress warning on Windows where 'self' isn't explicitly reassigned
    pub fn user<U: Into<User>>(mut self, user: U) -> Self {
        cfg_if! {
            if #[cfg(unix)] {
                self.user = Some(user.into());
            } else {
                let _ = user; // Evita warning de não utilizado
                if !self.suppress_unsupported_warnings {
                    eprintln!("Warning: Setting user is not supported on Windows in this manner and will be ignored.");
                }
            }
        }
        self
    }

    #[allow(unused_mut)] // Suppress warning on Windows where 'self' isn't explicitly reassigned
    pub fn group<G: Into<Group>>(mut self, group: G) -> Self {
        cfg_if! {
            if #[cfg(unix)] {
                self.group = Some(group.into());
            } else {
                let _ = group; // Evita warning de não utilizado
                if !self.suppress_unsupported_warnings {
                    eprintln!("Warning: Setting group is not supported on Windows in this manner and will be ignored.");
                }
            }
        }
        self
    }

    #[allow(unused_mut)] // Suppress warning on Windows where 'self' isn't explicitly reassigned
    pub fn umask<M: Into<Mask>>(mut self, mask: M) -> Self {
        cfg_if! {
            if #[cfg(unix)] {
                self.umask = mask.into();
            } else {
                let _ = mask; // Evita warning de não utilizado
                if !self.suppress_unsupported_warnings {
                    eprintln!("Warning: umask is not supported on Windows and will be ignored.");
                }
            }
        }
        self
    }

    #[allow(unused_mut)] // Suppress warning on Windows where 'self' isn't explicitly reassigned
    pub fn chroot<F: AsRef<Path>>(mut self, path: F) -> Self {
        cfg_if! {
            if #[cfg(unix)] {
                self.root = Some(path.as_ref().to_owned());
            } else {
                let _ = path; // Evita warning de não utilizado
                if !self.suppress_unsupported_warnings {
                    eprintln!("Warning: chroot is not supported on Windows and will be ignored.");
                }
            }
        }
        self
    }

    // Novo método para suprimir avisos em plataformas não suportadas
    #[cfg(windows)]
    pub fn suppress_unsupported_warnings(mut self, suppress: bool) -> Self {
        self.suppress_unsupported_warnings = suppress;
        self
    }


    pub fn privileged_action<N, F: FnOnce() -> N + 'static>(self, action: F) -> Daemonize<N> {
        let Daemonize {
            directory,
            pid_file,
            chown_pid_file,
            user,
            group,
            umask,
            root,
            privileged_action: _, // O antigo é descartado
            stdin,
            stdout,
            stderr,
            #[cfg(windows)]
            suppress_unsupported_warnings, // Captura o novo campo
        } = self;

        Daemonize {
            directory,
            pid_file,
            chown_pid_file,
            user,
            group,
            umask,
            root,
            privileged_action: Box::new(action), // Nova ação
            stdin,
            stdout,
            stderr,
            #[cfg(windows)]
            suppress_unsupported_warnings, // Propaga o novo campo
        }
    }


    pub fn stdout<S: Into<Stdio>>(mut self, stdio: S) -> Self {
        self.stdout = stdio.into();
        self
    }

    pub fn stderr<S: Into<Stdio>>(mut self, stdio: S) -> Self {
        self.stderr = stdio.into();
        self
    }

    pub fn stdin<S: Into<Stdio>>(mut self, stdio: S) -> Self {
        self.stdin = stdio.into();
        self
    }

    pub fn start(self) -> Result<T, Error> {
        // No Windows, o parent_mutex_handle_for_exit não é preenchido por execute na lógica atual
        // porque o processo pai original simplesmente sai.
        // Ele é passado por consistência de assinatura, mas o valor é descartado.
        #[cfg(windows)]
        let mut _windows_parent_mutex_handle_for_exit: Option<MutexHandle> = None;

        let execution_result = {
            cfg_if! {
                if #[cfg(windows)] {
                    self.execute(&mut _windows_parent_mutex_handle_for_exit)
                } else {
                    // Para Unix, o segundo argumento não é usado e não é necessário.
                    // Para manter uma assinatura única para execute, podemos passar um dummy,
                    // ou ter cfged execute signatures.
                    // Por agora, mantemos a assinatura única e o Unix ignora o param.
                    let mut dummy_mutex_handle_for_unix: Option<MutexHandle> = None;
                    self.execute(&mut dummy_mutex_handle_for_unix)
                }
            }
        };


        match execution_result {
            Outcome::Parent(parent_result) => {
                cfg_if! {
                    if #[cfg(unix)] {
                        match parent_result {
                            Ok(parent_data) => exit(parent_data.first_child_exit_code),
                            Err(e) => {
                                eprintln!("Daemonization failed in parent (Unix): {}", e);
                                exit(1); // Ou outro código de erro
                            }
                        }
                    } else if #[cfg(windows)] {
                        // No Windows, o processo pai original sai com sucesso após lançar o filho desanexado.
                        // O mutex relevante (se houver) foi tratado dentro de execute (pai original libera, filho mantém).
                        match parent_result {
                            Ok(_) => exit(0), // Pai original sai com sucesso
                            Err(e) => {
                                eprintln!("Daemonization failed in parent (Windows): {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        // Plataforma não suportada
                        match parent_result {
                            Ok(_) => exit(0),
                            Err(e) => {
                                eprintln!("Daemonization failed on unsupported platform: {}", e);
                                exit(1);
                            }
                        }
                    }
                }
            }
            Outcome::Child(Ok(child)) => Ok(child.privileged_action_result),
            Outcome::Child(Err(err)) => Err(err),
        }
    }

    // Adicionado _ para silenciar o warning de unused_variables, já que a lógica atual
    // não faz com que execute() modifique este parâmetro para o chamador start().
    pub fn execute(self, _parent_mutex_handle_storage: &mut Option<MutexHandle>) -> Outcome<T> {
        cfg_if! {
            if #[cfg(unix)] {
                // _parent_mutex_handle_storage é ignorado no Unix.
                unsafe {
                    match perform_fork_unix() {
                        Ok(Some(first_child_pid)) => {
                            Outcome::Parent(match waitpid_unix(first_child_pid) {
                                Err(err_kind) => Err(Error::new(err_kind)),
                                Ok(first_child_exit_code) => Ok(Parent { first_child_exit_code }),
                            })
                        },
                        Err(err_kind) => Outcome::Parent(Err(Error::new(err_kind))),
                        Ok(None) => match self.execute_child_unix() {
                            Ok(privileged_action_result) => Outcome::Child(Ok(Child {
                                privileged_action_result,
                            })),
                            Err(err_kind) => Outcome::Child(Err(Error::new(err_kind))),
                        },
                    }
                }
            } else if #[cfg(windows)] {
                let mut current_process_mutex: Option<MutexHandle> = None;

                // Tenta adquirir o mutex se um pid_file for especificado.
                // Isto serve como um "single instance lock" e verificação.
                if let Some(pid_path) = &self.pid_file {
                    match create_pid_file_windows(pid_path, true, &mut current_process_mutex) {
                        Ok(_) => { /* Mutex adquirido e armazenado em current_process_mutex */ }
                        Err(err_kind) => {
                            // Se o erro foi LockPidfile, significa que outra instância está rodando.
                            // O processo pai original deve sair.
                            return Outcome::Parent(Err(Error::new(err_kind)));
                        }
                    }
                }

                let needs_detach = unsafe { GetConsoleWindow() != (0 as HWND) };

                if needs_detach {
                    // Este é o processo pai original que tem uma consola e precisa desanexar.
                    // Ele deve liberar o mutex que acabou de adquirir (current_process_mutex),
                    // para que o filho desanexado possa adquiri-lo.
                    if let Some(mutex_to_release_by_parent) = current_process_mutex.take() {
                        unsafe {
                            if mutex_to_release_by_parent != INVALID_HANDLE_VALUE {
                                let _ = ReleaseMutex(mutex_to_release_by_parent);
                                CloseHandle(mutex_to_release_by_parent);
                            }
                        }
                    }
                    // _parent_mutex_handle_storage não é preenchido aqui, pois este processo pai está saindo.
                    match relaunch_detached_windows() {
                        Ok(process_id) => Outcome::Parent(Ok(Parent { child_process_id: Some(process_id) })),
                        Err(err_kind) => Outcome::Parent(Err(Error::new(err_kind))),
                    }
                } else {
                    // Este já é o processo filho (desanexado) ou o processo original não tinha consola.
                    // current_process_mutex (se Some) é o mutex que este processo agora possui.
                    // Passamos a posse do current_process_mutex para execute_child_windows.
                    match self.execute_child_windows(current_process_mutex) {
                        Ok(privileged_action_result) => Outcome::Child(Ok(Child {
                            privileged_action_result,
                        })),
                        Err(err_kind) => {
                            // Se execute_child_windows falhar, o mutex (current_process_mutex)
                            // já foi consumido e deveria ter sido liberado dentro de execute_child_windows.
                            Outcome::Child(Err(Error::new(err_kind)))
                        }
                    }
                }
            } else {
                Outcome::Parent(Err(Error::new(ErrorKind::Custom("Unsupported platform".to_string()))))
            }
        }
    }

    #[cfg(unix)]
    fn execute_child_unix(self) -> Result<T, ErrorKind> {
        unsafe {
            set_current_dir(&self.directory).map_err(|e| ErrorKind::ChangeDirectory(e.raw_os_error().unwrap_or(0)))?;
            set_sid_unix()?;
            libc::umask(self.umask.inner);

            if perform_fork_unix()?.is_some() { // Segundo fork
                exit(0) // Processo intermediário (primeiro filho) sai
            };

            // Agora estamos no processo neto (o daemon final)
            let mut pid_file_handle: Option<RawFd> = None;
            if let Some(ref pid_file_path) = self.pid_file {
                let fd = create_pid_file_unix(pid_file_path)?;
                pid_file_handle = Some(fd);
            }

            // Consome self.stdin, self.stdout, self.stderr
            redirect_standard_streams_unix(self.stdin, self.stdout, self.stderr)?;

            let uid = self.user.map(|user| get_user_unix(user)).transpose()?;
            let gid = self.group.map(|group| get_group_unix(group)).transpose()?;

            if self.chown_pid_file {
                if let (Some(ref pid_f_path), maybe_uid_val, maybe_gid_val) = (&self.pid_file, uid, gid) {
                    // chown requer uid e gid. Se um não for especificado, use -1 (ou !0) para "não mudar".
                    let final_uid = maybe_uid_val.unwrap_or(!0);
                    let final_gid = maybe_gid_val.unwrap_or(!0);
                    if maybe_uid_val.is_some() || maybe_gid_val.is_some() { // Apenas chown se user ou group foi dado
                        chown_pid_file_unix(pid_f_path, final_uid, final_gid)?;
                    }
                }
            }

            if let Some(fd) = pid_file_handle {
                set_cloexec_pid_file_unix(fd)?;
            }

            let privileged_action_result = (self.privileged_action)();

            if let Some(ref root_path) = self.root {
                change_root_unix(root_path)?;
            }

            if let Some(gid_val) = gid {
                set_group_unix(gid_val)?;
            }

            if let Some(uid_val) = uid {
                set_user_unix(uid_val)?;
            }

            if let Some(fd) = pid_file_handle {
                write_pid_file_unix(fd)?;
                // O fd do pid_file é mantido aberto e bloqueado pelo daemon.
                // `std::mem::forget(fd)` garante que o RawFd não é fechado quando sai do escopo.
                std::mem::forget(fd);
            }

            Ok(privileged_action_result)
        }
    }

    #[cfg(windows)]
    fn execute_child_windows(self, owned_child_mutex_handle: Option<MutexHandle>) -> Result<T, ErrorKind> {
        let mut mutex_to_manage = owned_child_mutex_handle;

        let dir_path_win: Vec<u16> = self.directory.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { SetCurrentDirectoryW(dir_path_win.as_ptr()) } == 0 { // FALSE
            let err_code = error::get_last_windows_api_error_kind("SetCurrentDirectoryW_child_exec").get_os_error_code().unwrap_or(0);
            eprintln!("[DEBUG - CHDIR] SetCurrentDirectoryW failed for path {:?} with code: {}", self.directory, err_code);
            let err_kind = error::get_last_windows_api_error_kind("SetCurrentDirectoryW_child_exec");
            if let Some(mutex) = mutex_to_manage.take() { if mutex != INVALID_HANDLE_VALUE { unsafe { let _ = ReleaseMutex(mutex); CloseHandle(mutex); }}}
            return Err(err_kind);
        }

        // Se o mutex não foi passado (ex: pid_file não configurado antes do relaunch),
        // tenta adquiri-lo agora.
        if mutex_to_manage.is_none() && self.pid_file.is_some() {
            match create_pid_file_windows(self.pid_file.as_ref().unwrap(), true, &mut mutex_to_manage) {
                Ok(_) => {}
                Err(err_kind) => {
                    // create_pid_file_windows deve limpar o mutex em caso de erro interno.
                    // Se falhou aqui, é um erro de daemonização.
                    return Err(err_kind);
                }
            }
        }

        // Escreve o PID no ficheiro PID se um mutex foi obtido (indicando que o lock está ativo)
        // e um pid_file foi especificado.
        if self.pid_file.is_some() && mutex_to_manage.is_some() {
            if let Err(e) = write_pid_file_windows(self.pid_file.as_ref().unwrap()) {
                if let Some(mutex) = mutex_to_manage.take() { if mutex != INVALID_HANDLE_VALUE { unsafe { let _ = ReleaseMutex(mutex); CloseHandle(mutex); }}}
                return Err(e);
            }
        }

        // Consome self.stdin, self.stdout, self.stderr
        if let Err(e) = redirect_standard_streams_windows(self.stdin, self.stdout, self.stderr) {
            if let Some(mutex) = mutex_to_manage.take() { if mutex != INVALID_HANDLE_VALUE { unsafe { let _ = ReleaseMutex(mutex); CloseHandle(mutex); }}}
            return Err(e);
        }

        // Funcionalidades não suportadas/ignoradas no Windows
        if !self.suppress_unsupported_warnings {
            if self.user.is_some() || self.group.is_some() {
                eprintln!("Warning: Setting user/group is not implemented for Windows in this version and will be ignored.");
            }
            if self.chown_pid_file && (self.user.is_some() || self.group.is_some()) {
                eprintln!("Warning: chown_pid_file is not supported on Windows and will be ignored.");
            }
            if self.umask.inner != 0o027 { // Se não for o padrão Unix
                eprintln!("Warning: umask is not supported on Windows and will be ignored.");
            }
            if self.root.is_some() {
                eprintln!("Warning: chroot is not supported on Windows and will be ignored.");
            }
        }

        let privileged_action_result = (self.privileged_action)();

        // O mutex é mantido pelo processo filho desanexado.
        // `std::mem::forget` impede que o handle do mutex seja fechado quando `mutex_to_manage` sai do escopo.
        // O SO o liberará quando o processo terminar.
        if let Some(mutex) = mutex_to_manage.take() {
            if mutex != INVALID_HANDLE_VALUE {
                // `std::mem::forget` é usado para transferir a posse do handle para o processo atual.
                // Ele não será fechado automaticamente quando `mutex` sair do escopo,
                // e o SO o fechará quando o processo terminar.
                let _ = mutex;
            }
        }

        Ok(privileged_action_result)
    }
}

// --- Funções Auxiliares Específicas do Unix ---
#[cfg(unix)]
unsafe fn perform_fork_unix() -> Result<Option<libc::pid_t>, ErrorKind> {
    let pid = error::check_err(libc::fork(), ErrorKind::Fork)?;
    if pid == 0 { Ok(None) } else { Ok(Some(pid)) }
}

#[cfg(unix)]
unsafe fn waitpid_unix(pid: libc::pid_t) -> Result<i32, ErrorKind> { // Alterado para i32 para consistência com Parent struct
    let mut child_ret_status = 0;
    error::check_err(libc::waitpid(pid, &mut child_ret_status, 0), ErrorKind::Wait)?;
    // Extrair o código de saída real se o processo terminou normalmente
    if libc::WIFEXITED(child_ret_status) {
        Ok(libc::WEXITSTATUS(child_ret_status))
    } else {
        // Se terminou por sinal ou outra forma, podemos retornar um código genérico ou o status bruto
        Ok(1) // Ou child_ret_status se quiser o status bruto
    }
}

#[cfg(unix)]
unsafe fn set_sid_unix() -> Result<(), ErrorKind> {
    error::check_err(libc::setsid(), ErrorKind::DetachSession)?;
    Ok(())
}

#[cfg(unix)]
unsafe fn redirect_standard_streams_unix(
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<(), ErrorKind> {
    let devnull_fd = error::check_err(
        libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR),
        ErrorKind::OpenDeviceNull,
    )?;

    // A closure não precisa ser mutável aqui.
    let process_stdio = |fd: RawFd, stdio_cfg: Stdio| -> Result<(), ErrorKind> {
        match stdio_cfg.inner { // stdio_cfg.inner é movido aqui
            StdioImpl::Devnull => {
                error::check_err(libc::dup2(devnull_fd, fd), ErrorKind::RedirectStreams)?;
            }
            StdioImpl::RedirectToFile(file) => { // file é movido aqui
                let raw_fd = file.as_raw_fd(); // as_raw_fd() empresta, into_raw_fd() consome
                                               // Se StdioImpl::RedirectToFile(file: File), file é movido para o match.
                                               // file.as_raw_fd() não consome, mas o File original é movido para o pattern.
                                               // Para evitar problemas com a vida útil de `file` se `Stdio` for reutilizado,
                                               // é melhor consumir `file` aqui, o que `into_raw_fd` faria.
                                               // No entanto, `as_raw_fd` é suficiente se `file` não for mais usado.
                                               // A struct Stdio é consumida por redirect_standard_streams_unix, então está ok.
                error::check_err(libc::dup2(raw_fd, fd), ErrorKind::RedirectStreams)?;
                // O `file` original sairá do escopo e será fechado se não for esquecido,
                // mas `dup2` cria uma cópia do descritor, então o original pode ser fechado.
            }
            StdioImpl::Keep => (),
        };
        Ok(())
    };

    process_stdio(libc::STDIN_FILENO, stdin)?;
    process_stdio(libc::STDOUT_FILENO, stdout)?;
    process_stdio(libc::STDERR_FILENO, stderr)?;

    error::check_err(libc::close(devnull_fd), ErrorKind::CloseDeviceNull)?;
    Ok(())
}

#[cfg(unix)]
unsafe fn get_group_unix(group_info: Group) -> Result<libc::gid_t, ErrorKind> {
    match group_info.inner { // group_info.inner é movido aqui
        GroupImpl::Id(id) => Ok(id),
        GroupImpl::Name(name) => { // name é movido aqui
            let s = CString::new(name).map_err(|_| ErrorKind::GroupContainsNul)?;
            let grp_ptr = libc::getgrnam(s.as_ptr());
            if grp_ptr.is_null() {
                Err(ErrorKind::GroupNotFound)
            } else {
                Ok((*grp_ptr).gr_gid)
            }
        }
    }
}


#[cfg(unix)]
unsafe fn set_group_unix(group: libc::gid_t) -> Result<(), ErrorKind> {
    error::check_err(libc::setgid(group), ErrorKind::SetGroup)?;
    Ok(())
}

#[cfg(unix)]
unsafe fn get_user_unix(user_info: User) -> Result<libc::uid_t, ErrorKind> {
   match user_info.inner { // user_info.inner é movido aqui
        UserImpl::Id(id) => Ok(id),
        UserImpl::Name(name) => { // name é movido aqui
            let s = CString::new(name).map_err(|_| ErrorKind::UserContainsNul)?;
            let pwd_ptr = libc::getpwnam(s.as_ptr());
            if pwd_ptr.is_null() {
                Err(ErrorKind::UserNotFound)
            } else {
                Ok((*pwd_ptr).pw_uid)
            }
        }
    }
}

#[cfg(unix)]
unsafe fn set_user_unix(user: libc::uid_t) -> Result<(), ErrorKind> {
    error::check_err(libc::setuid(user), ErrorKind::SetUser)?;
    Ok(())
}

#[cfg(unix)]
fn pathbuf_into_cstring_unix(path: &Path) -> Result<CString, ErrorKind> {
    // Use as_os_str().as_bytes() para Unix, que é geralmente compatível com Vec<u8> para CString
    CString::new(path.as_os_str().as_bytes()).map_err(|_| ErrorKind::PathContainsNul)
}

#[cfg(unix)]
unsafe fn create_pid_file_unix(path: &Path) -> Result<RawFd, ErrorKind> {
    let path_c = pathbuf_into_cstring_unix(path)?;
    let fd = error::check_err(
        libc::open(path_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o666), // Adicionado O_TRUNC
        ErrorKind::OpenPidfile,
    )?;

    let flock_res = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB);
    if flock_res == -1 { // flock retorna 0 em sucesso, -1 em erro.
        let os_err = error::get_last_os_error();
        libc::close(fd); // Importante fechar o fd se o lock falhar.
        return Err(ErrorKind::LockPidfile(os_err));
    }
    Ok(fd)
}

#[cfg(unix)]
unsafe fn chown_pid_file_unix(
    path: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), ErrorKind> {
    let path_c = pathbuf_into_cstring_unix(path)?;
    error::check_err(libc::chown(path_c.as_ptr(), uid, gid), ErrorKind::ChownPidfile)?;
    Ok(())
}

#[cfg(unix)]
unsafe fn write_pid_file_unix(fd: RawFd) -> Result<(), ErrorKind> {
    let pid = libc::getpid();
    let pid_buf = format!("{}\n", pid).into_bytes();
    // ftruncate não é necessário se O_TRUNC foi usado em open, mas não faz mal.
    error::check_err(libc::ftruncate(fd, 0), ErrorKind::TruncatePidfile)?;
    // Reposicionar o cursor para o início do arquivo antes de escrever
    error::check_err(libc::lseek(fd, 0, libc::SEEK_SET), ErrorKind::TruncatePidfile)?;


    let written = error::check_err(
        libc::write(fd, pid_buf.as_ptr() as *const libc::c_void, pid_buf.len()),
        ErrorKind::WritePid,
    )?;
    if written < pid_buf.len() as isize {
        Err(ErrorKind::WritePidUnspecifiedError)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
unsafe fn set_cloexec_pid_file_unix(fd: RawFd) -> Result<(), ErrorKind> {
    if cfg!(not(target_os = "redox")) {
        let flags = error::check_err(libc::fcntl(fd, libc::F_GETFD), ErrorKind::GetPidfileFlags)?;
        error::check_err(
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC),
            ErrorKind::SetPidfileFlags,
        )?;
    } else {
        // Para Redox, FIOCLEX pode ser usado, mas precisa da definição correta de FIOCLEX.
        // Se não estiver disponível ou não implementado, pode ser um no-op com aviso.
        // Exemplo: error::check_err(libc::ioctl(fd, libc::FIOCLEX as _), ErrorKind::SetPidfileFlags)?;
        eprintln!("Warning: Redox FIOCLEX for pid_file not fully implemented in this example for set_cloexec_pid_file_unix.");
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn change_root_unix(path: &Path) -> Result<(), ErrorKind> {
    let path_c = pathbuf_into_cstring_unix(path)?;
    error::check_err(libc::chroot(path_c.as_ptr()), ErrorKind::Chroot)?;
    Ok(())
}


// --- Funções Auxiliares Específicas do Windows ---
#[cfg(windows)]
fn to_wstring(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn relaunch_detached_windows() -> Result<u32, ErrorKind> {
    unsafe {
        let mut module_path_buf = vec![0u16; 1024];
        let len = GetModuleFileNameW(0 as _, module_path_buf.as_mut_ptr(), module_path_buf.len() as u32);
        if len == 0 || len == module_path_buf.len() as u32 {
            return Err(error::get_last_windows_api_error_kind("GetModuleFileNameW_relaunch"));
        }

        // Construir a linha de comando completa incluindo o executável e TODOS os argumentos originais
        let current_args: Vec<String> = std::env::args().collect(); // Captura todos os args do processo atual
        let mut full_command_line_str = String::new();

        // Iterar sobre os argumentos e construí-los na string de linha de comando.
        // Cuidar de espaços em argumentos (citar). Esta é uma citação básica.
        for (i, arg) in current_args.iter().enumerate() {
            if i > 0 { // Adicionar espaço entre argumentos
                full_command_line_str.push(' ');
            }
            // Citar o argumento se ele contiver espaços ou já tiver aspas
            if arg.contains(' ') || arg.contains('"') {
                full_command_line_str.push('"');
                // Escapar aspas internas se houverem
                full_command_line_str.push_str(&arg.replace('"', "\\\""));
                full_command_line_str.push('"');
            } else {
                full_command_line_str.push_str(arg);
            }
        }

        let mut command_line_w = to_wstring(&full_command_line_str); // Converte par
            
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        // Para processos desanexados, é bom não herdar handles e não mostrar janela.
        // si.dwFlags = STARTF_USESTDHANDLES; // Se quiser controlar handles, mas aqui não precisamos.
        // si.hStdInput, si.hStdOutput, si.hStdError devem ser NULL ou inválidos para não herdar.
        // O comportamento padrão de CreateProcess sem STARTF_USESTDHANDLES para DETACHED_PROCESS
        // é não herdar os std handles da consola do pai.

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // module_path_buf já é null-terminated por GetModuleFileNameW se len < buf.len()
        // Se len == buf.len(), pode não ser. Mas GetModuleFileNameW deve retornar o tamanho sem o null.
        // Para CreateProcessW, o lpApplicationName pode ser null se lpCommandLine tiver o executável.
        // lpCommandLine deve ser mutável.
        let mut command_line = module_path_buf[..(len as usize)].to_vec();
        command_line.push(0); // Garante terminação nula para CreateProcessW

        if CreateProcessW(
            ptr::null(), // Pode ser o nome do executável aqui também
            command_line_w.as_mut_ptr(), // Linha de comando completa (incluindo executável)
            ptr::null_mut(), // Atributos de segurança do processo (padrão)
            ptr::null_mut(), // Atributos de segurança do thread (padrão)
            0,   // bInheritHandles = FALSE (não herda handles)
            DETACHED_PROCESS | CREATE_NO_WINDOW, // Flags de criação
            ptr::null_mut(), // Bloco de ambiente (herda do pai)
            ptr::null(),     // Diretório atual (herda do pai)
            &mut si,
            &mut pi,
        ) == 0 { // FALSE em caso de erro
            Err(error::get_last_windows_api_error_kind("CreateProcessW_relaunch_detached"))
        } else {
            // Fechar os handles do processo e thread filho no pai, pois não precisamos deles.
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Ok(pi.dwProcessId)
        }
    }
}

#[cfg(windows)]
fn create_pid_file_windows(path: &Path, acquire_lock_now: bool, mutex_handle_out: &mut Option<MutexHandle>) -> Result<(), ErrorKind> {
    // Cria um nome de mutex único baseado no caminho do ficheiro.
    // Substitui caracteres inválidos para nomes de objetos do kernel.
    let mutex_name_str = path.to_string_lossy().replace(['\\', ':', '/'], "_");
    // Adiciona prefixo "Global\\" para mutexes nomeados no escopo global.
    let mutex_name_w = to_wstring(&format!("Global\\DaemonizePlus_{}", mutex_name_str));

    unsafe {
        let mutex = CreateMutexW(ptr::null_mut(), 0, mutex_name_w.as_ptr()); // Tenta criar ou abrir o mutex
        if mutex.is_null() || mutex == INVALID_HANDLE_VALUE { // Corrected check for null pointer
            return Err(error::get_last_windows_api_error_kind("CreateMutexW_pid_creation"));
        }

        if acquire_lock_now {
            let wait_result = WaitForSingleObject(mutex, 0); // Tenta adquirir o lock (timeout 0)
            if wait_result == WAIT_TIMEOUT {
                // Outro processo já tem o lock.
                CloseHandle(mutex); // Libera o handle do mutex que acabamos de criar/abrir.
                return Err(ErrorKind::LockPidfile(WAIT_TIMEOUT as i32));
            } else if !(wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED) {
                // Erro inesperado ao esperar pelo mutex.
                let err_kind = error::get_last_windows_api_error_kind("WaitForSingleObject_pid_lock");
                CloseHandle(mutex);
                return Err(err_kind);
            }
            // Se WAIT_ABANDONED, o mutex foi adquirido, mas o processo anterior terminou sem liberá-lo.
            // Para um lock de PID, isto é geralmente tratado como aquisição bem-sucedida.
        }
        *mutex_handle_out = Some(mutex);
        Ok(())
    }
}


#[cfg(windows)]
fn write_pid_file_windows(path: &Path) -> Result<(), ErrorKind> {
    let pid = unsafe { GetCurrentProcessId() };
    let content = format!("{}\n", pid);
    let path_w = to_wstring(&path.to_string_lossy());

    unsafe {
        // Tenta criar um novo ficheiro. Se já existir, falha (CREATE_NEW).
        // Isso é para garantir que não sobrescrevemos um PID file de outro processo sem querer
        // se o lock (mutex) falhou ou não foi usado corretamente.
        // A lógica de lock com mutex é a principal para "single instance".
        // O ficheiro PID é mais para informação.
        let file_handle = CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, // Permite que outros leiam o PID file
            ptr::null_mut(),
            CREATE_ALWAYS, // Cria se não existir, falha se existir
            FILE_ATTRIBUTE_NORMAL,
            0 as _,
        );

        if file_handle == INVALID_HANDLE_VALUE {
            let err_code = error::get_last_windows_api_error_kind("CreateFileW_pid_write_CREATE_ALWAYS_failed").get_os_error_code().unwrap_or(0);
            eprintln!("[DEBUG - PID FILE] CreateFileW (CREATE_ALWAYS) failed with code: {}", err_code);
            return Err(error::get_last_windows_api_error_kind("CreateFileW_pid_write"));
        }
        let final_handle = file_handle;

        /* let final_handle = if file_handle == INVALID_HANDLE_VALUE {
            // Se CREATE_NEW falhou (provavelmente porque o ficheiro já existe),
            // tenta abri-lo para sobrescrever (TRUNCATE_EXISTING).
            let existing_handle = CreateFileW(
                path_w.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                TRUNCATE_EXISTING, // Abre e trunca se existir
                FILE_ATTRIBUTE_NORMAL,
                0 as _,
            );
            if existing_handle == INVALID_HANDLE_VALUE {
                let truncate_existing_err_code = error::get_last_windows_api_error_kind("CreateFileW_pid_write_TRUNCATE_EXISTING").get_os_error_code().unwrap_or(0);
                eprintln!("[DEBUG - PID FILE] CreateFileW (TRUNCATE_EXISTING) failed with code: {}", truncate_existing_err_code);
                return Err(error::get_last_windows_api_error_kind("CreateFileW_pid_write_open_existing"));
            }
            existing_handle
        } else {
            file_handle
        }; */

        let mut bytes_written = 0;
        if WriteFile(
            final_handle,
            content.as_ptr() as _, // Conteúdo a escrever
            content.len() as u32,  // Número de bytes a escrever
            &mut bytes_written,    // Número de bytes escritos
            ptr::null_mut(),       // Para operações síncronas
        ) == 0 || bytes_written != content.len() as u32 { // FALSE em erro ou se nem todos os bytes foram escritos
            let err = error::get_last_windows_api_error_kind("WriteFile_pid_content");
            CloseHandle(final_handle);
            return Err(err);
        }

        let _ = FlushFileBuffers(final_handle); // Garante que os dados são escritos no disco. Ignora resultado.
        CloseHandle(final_handle); // Fecha o handle do ficheiro.
    }
    Ok(())
}


#[cfg(windows)]
fn redirect_standard_streams_windows(
    stdin_cfg: Stdio,
    stdout_cfg: Stdio,
    stderr_cfg: Stdio,
) -> Result<(), ErrorKind> {
    unsafe {
        let process_stdio = |std_handle_type: u32, cfg: Stdio| -> Result<(), ErrorKind> {
            // Determina o handle de destino e se era para DevNull ANTES de consumir cfg.inner.
            let (target_handle, was_devnull): (HANDLE, bool) = match cfg.inner {
                StdioImpl::Devnull => {
                    let h = CreateFileW(
                        to_wstring("NUL").as_ptr(),
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE, // NUL precisa de R/W
                        FILE_SHARE_READ | FILE_SHARE_WRITE, // Compartilhamento para NUL
                        ptr::null_mut(),
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        0 as _,
                    );
                    if h == INVALID_HANDLE_VALUE {
                        return Err(error::get_last_windows_api_error_kind("CreateFileW_NUL_redirect"));
                    }
                    (h, true)
                }
                StdioImpl::RedirectToFile(file) => { // `file` (tipo File) é movido aqui
                    // into_raw_handle() consome `file` e transfere posse do handle.
                    (file.into_raw_handle() as HANDLE, false)
                }
                StdioImpl::Keep => return Ok(()), // Nada a fazer, retorna cedo.
            };

            if SetStdHandle(std_handle_type, target_handle) == 0 { // FALSE em erro
                if target_handle != INVALID_HANDLE_VALUE {
                    // Se SetStdHandle falhou, o target_handle (seja de NUL ou de File)
                    // não foi assumido pelo sistema, então precisamos fechá-lo.
                    CloseHandle(target_handle);
                }
                return Err(error::get_last_windows_api_error_kind("SetStdHandle_redirect"));
            }

            // Se SetStdHandle foi bem-sucedido:
            if was_devnull {
                // O handle para NUL foi criado por nós e SetStdHandle (espera-se) o duplicou.
                // Podemos fechar o nosso handle original.
                // Não precisamos de `std::mem::forget` aqui, pois SetStdHandle duplica o handle,
                // e nós queremos fechar o nosso handle original para o NUL.
                if target_handle != INVALID_HANDLE_VALUE { CloseHandle(target_handle); }
            }
            // Se era RedirectToFile, o handle foi transferido de `File` via `into_raw_handle`
            // e agora é propriedade do sistema como o std handle. Não o fechamos aqui,
            // e `std::mem::forget` não é necessário porque `into_raw_handle` já transferiu a posse.
            Ok(())
        };

        process_stdio(STD_INPUT_HANDLE, stdin_cfg)?;
        process_stdio(STD_OUTPUT_HANDLE, stdout_cfg)?;
        process_stdio(STD_ERROR_HANDLE, stderr_cfg)?;
    }
    Ok(())
}