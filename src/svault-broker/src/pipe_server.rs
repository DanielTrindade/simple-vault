use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use zeroize::Zeroizing;

use svault_core::logging::VaultLog;
use svault_core::paths;
use svault_core::protocol::{Envelope, EnvelopeResponse, MAX_REQUEST_BYTES, error_codes};

use crate::engine::BrokerEngine;

const INSTANCE_COUNT: usize = 4;
const READ_TIMEOUT_SECONDS: u64 = 30;

#[cfg(windows)]
pub struct PipeSecurityDescriptor {
    sd_ptr: *mut std::ffi::c_void,
}

#[cfg(windows)]
unsafe impl Send for PipeSecurityDescriptor {}
#[cfg(windows)]
unsafe impl Sync for PipeSecurityDescriptor {}

#[cfg(windows)]
impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.sd_ptr.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.sd_ptr);
            }
        }
    }
}

#[cfg(windows)]
impl PipeSecurityDescriptor {
    pub fn build(owner_sid: &str, allowed_client_sids: &[String]) -> io::Result<Self> {
        use std::ptr;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        // PipeAccessRights.ReadWrite = 0x0012019B; + CreateNewInstance (0x04) = 0x0012019F.
        const SERVER_RIGHTS: &str = "0x0012019F";
        const CLIENT_RIGHTS: &str = "0x0012019B";

        let mut sddl = String::from("D:P");
        sddl.push_str(&format!("(A;;{SERVER_RIGHTS};;;SY)"));
        sddl.push_str(&format!("(A;;{SERVER_RIGHTS};;;BA)"));

        if is_valid_sid(owner_sid)
            && !owner_sid.eq_ignore_ascii_case("S-1-5-18")
            && !owner_sid.eq_ignore_ascii_case("S-1-5-32-544")
        {
            sddl = format!("O:{owner_sid}{sddl}(A;;{SERVER_RIGHTS};;;{owner_sid})");
        }

        let mut seen: Vec<String> = Vec::new();
        for sid in allowed_client_sids {
            let trimmed = sid.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("S-1-5-18")
                || trimmed.eq_ignore_ascii_case("S-1-5-32-544")
                || trimmed.eq_ignore_ascii_case(owner_sid)
                || seen.iter().any(|s| s.eq_ignore_ascii_case(trimmed))
            {
                continue;
            }
            if is_valid_sid(trimmed) {
                sddl.push_str(&format!("(A;;{CLIENT_RIGHTS};;;{trimmed})"));
                seen.push(trimmed.to_owned());
            }
        }

        let sddl_wide = wide_null(&sddl);
        let mut sd_ptr = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                ptr::null_mut(),
            )
        };
        if ok == 0 || sd_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { sd_ptr })
    }

    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.sd_ptr
    }
}

#[cfg(windows)]
pub fn current_process_sid() -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return None;
    }

    let mut needed: u32 = 0;
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        unsafe { CloseHandle(token) };
        return None;
    }

    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return None;
    }

    let token_user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut str_ptr: *mut u16 = ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut str_ptr) };
    if converted == 0 || str_ptr.is_null() {
        return None;
    }

    let sid = unsafe { wide_ptr_to_string(str_ptr) };
    unsafe { LocalFree(str_ptr.cast()) };
    Some(sid)
}

#[cfg(windows)]
pub struct PipeServer {
    pipe_path: String,
    security: Arc<PipeSecurityDescriptor>,
    engine: Arc<BrokerEngine>,
    log: Arc<VaultLog>,
}

#[cfg(windows)]
impl PipeServer {
    pub fn new(
        pipe_name: &str,
        security: Arc<PipeSecurityDescriptor>,
        engine: Arc<BrokerEngine>,
        log: Arc<VaultLog>,
    ) -> Self {
        Self {
            pipe_path: paths::pipe_path(pipe_name),
            security,
            engine,
            log,
        }
    }

    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let first = self.create_instance(true)?;
        let mut initial_servers = Vec::with_capacity(INSTANCE_COUNT);
        initial_servers.push(first);
        for _ in 1..INSTANCE_COUNT {
            initial_servers.push(self.create_instance(false)?);
        }

        let mut handles = Vec::with_capacity(INSTANCE_COUNT);
        for server in initial_servers {
            let pipe_path = self.pipe_path.clone();
            let security = Arc::clone(&self.security);
            let engine = Arc::clone(&self.engine);
            let log = Arc::clone(&self.log);
            let mut worker_shutdown = shutdown.clone();

            handles.push(tokio::spawn(async move {
                accept_loop(
                    server,
                    &pipe_path,
                    &security,
                    &engine,
                    &log,
                    &mut worker_shutdown,
                )
                .await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
        Ok(())
    }

    fn create_instance(
        &self,
        first: bool,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        create_pipe_instance(&self.pipe_path, &self.security, first)
    }
}

#[cfg(windows)]
fn create_pipe_instance(
    pipe_path: &str,
    security: &PipeSecurityDescriptor,
    first: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.as_ptr(),
        bInheritHandle: 0,
    };

    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first)
        .access_inbound(true)
        .access_outbound(true)
        .pipe_mode(PipeMode::Byte)
        .in_buffer_size(4096)
        .out_buffer_size(4096);

    unsafe {
        opts.create_with_security_attributes_raw(
            pipe_path,
            (&mut sa as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
}

#[cfg(windows)]
async fn accept_loop(
    mut current: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe_path: &str,
    security: &PipeSecurityDescriptor,
    engine: &BrokerEngine,
    log: &VaultLog,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }

        let connected = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
                continue;
            }
            res = current.connect() => res,
        };

        if let Err(err) = connected {
            log.write(
                "pipe_error",
                [
                    ("type", json!("IoError")),
                    ("message", json!(err.to_string())),
                    ("osError", json!(err.raw_os_error())),
                ],
            );
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        } else {
            let client_sid = resolve_client_sid(&current);
            let read_result = tokio::time::timeout(
                Duration::from_secs(READ_TIMEOUT_SECONDS),
                read_frame_async(&mut current, MAX_REQUEST_BYTES),
            )
            .await;

            match read_result {
                Err(_) => {
                    log.write("pipe_timeout", [("client", json!(client_sid))]);
                }
                Ok(Err(err)) => {
                    log.write(
                        "pipe_client_error",
                        [
                            ("type", json!(format!("{:?}", err.kind()))),
                            ("client", json!(client_sid)),
                        ],
                    );
                }
                Ok(Ok(request_bytes)) => {
                    let response_bytes = handle_payload(&request_bytes, &client_sid, engine, log).await;
                    if let Err(err) = write_frame_async(&mut current, &response_bytes).await {
                        log.write(
                            "pipe_client_error",
                            [
                                ("type", json!(format!("{:?}", err.kind()))),
                                ("client", json!(client_sid)),
                            ],
                        );
                    } else {
                        // Wait for client to finish reading and close its handle instead of calling
                        // DisconnectNamedPipe, which would purge unread bytes and cause OS error 233.
                        let mut eof = [0u8; 1];
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            current.read(&mut eof),
                        )
                        .await;
                    }
                }
            }
        }

        if *shutdown.borrow() {
            break;
        }

        loop {
            match create_pipe_instance(pipe_path, security, false) {
                Ok(next) => {
                    // Replace `current` after creating `next` so there is never a 0-instance gap,
                    // and drop the old handle cleanly via CloseHandle without DisconnectNamedPipe.
                    current = next;
                    break;
                }
                Err(err) => {
                    log.write(
                        "pipe_error",
                        [
                            ("type", json!("CreateInstanceError")),
                            ("message", json!(err.to_string())),
                        ],
                    );
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                }
            }
        }
    }
}

async fn handle_payload(
    request_bytes: &[u8],
    client_sid: &str,
    engine: &BrokerEngine,
    log: &VaultLog,
) -> Vec<u8> {
    let response = match serde_json::from_slice::<Envelope>(request_bytes) {
        Ok(envelope) if !envelope.cmd.trim().is_empty() => {
            engine.handle_async(envelope, client_sid).await
        }
        Ok(_) => EnvelopeResponse::failure(error_codes::BAD_REQUEST, "Comando desconhecido: "),
        Err(err) => {
            log.write("request_error", [("type", json!(err.to_string()))]);
            EnvelopeResponse::failure(error_codes::BAD_REQUEST, "Envelope invalido.")
        }
    };

    serde_json::to_vec(&response).unwrap_or_else(|_| {
        br#"{"ok":false,"error":{"code":"internal_error","message":"Falha interna no broker."}}"#
            .to_vec()
    })
}

async fn read_frame_async<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let length = i32::from_le_bytes(header);
    if length <= 0 || length as usize > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Tamanho de mensagem invalido.",
        ));
    }
    let mut payload = Zeroizing::new(vec![0u8; length as usize]);
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame_async<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Resposta grande demais."))?;
    writer.write_all(&length.to_le_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

#[cfg(windows)]
fn resolve_client_sid(server: &tokio::net::windows::named_pipe::NamedPipeServer) -> String {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pipe_handle = server.as_raw_handle();
    let mut client_pid: u32 = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle.cast(), &mut client_pid) } == 0
        || client_pid == 0
    {
        return "unknown".to_owned();
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) };
    if process.is_null() {
        return "unknown".to_owned();
    }

    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        unsafe { CloseHandle(process) };
        return "unknown".to_owned();
    }

    let mut needed: u32 = 0;
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        unsafe {
            CloseHandle(token);
            CloseHandle(process);
        }
        return "unknown".to_owned();
    }

    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    if ok == 0 {
        return "unknown".to_owned();
    }

    let token_user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut str_ptr: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut str_ptr) } == 0
        || str_ptr.is_null()
    {
        return "unknown".to_owned();
    }

    let sid = unsafe { wide_ptr_to_string(str_ptr) };
    unsafe { LocalFree(str_ptr.cast()) };
    sid
}

#[cfg(windows)]
fn is_valid_sid(sid: &str) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

    if sid.trim().is_empty() {
        return false;
    }
    let wide = wide_null(sid);
    let mut ptr_sid = ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut ptr_sid) };
    if ok != 0 && !ptr_sid.is_null() {
        unsafe { LocalFree(ptr_sid) };
        true
    } else {
        false
    }
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    use std::os::windows::ffi::OsStringExt;
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::ffi::OsString::from_wide(slice)
        .to_string_lossy()
        .into_owned()
}
