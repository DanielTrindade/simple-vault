use std::io;

use crate::storage::CredentialStore;

pub struct CredentialManagerApi;

impl CredentialManagerApi {
    pub fn build_target(prefix: &str, id: &str) -> String {
        format!("{prefix}:{id}")
    }

    pub fn describe_scope() -> &'static str {
        "Windows Credential Manager (DPAPI, perfil da conta proprietaria do cofre)"
    }

    #[cfg(windows)]
    pub fn write(target: &str, user_name: &str, secret: &[u8]) -> io::Result<()> {
        use std::ptr;
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
        };
        use zeroize::Zeroizing;

        let mut target_wide = wide_null(target);
        let mut user_wide = wide_null(user_name);
        let mut blob_copy = Zeroizing::new(secret.to_vec());

        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_wide.as_mut_ptr(),
            Comment: ptr::null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob_copy.len() as u32,
            CredentialBlob: if blob_copy.is_empty() {
                ptr::null_mut()
            } else {
                blob_copy.as_mut_ptr()
            },
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: user_wide.as_mut_ptr(),
        };

        let ok = unsafe { CredWriteW(&credential, 0) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn read(target: &str) -> io::Result<Option<Vec<u8>>> {
        use std::ptr;
        use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
        use windows_sys::Win32::Security::Credentials::{
            CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
        };

        let target_wide = wide_null(target);
        let mut cred_ptr: *mut CREDENTIALW = ptr::null_mut();
        let ok = unsafe { CredReadW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(None);
            }
            return Err(err);
        }

        let result = unsafe {
            let cred = &*cred_ptr;
            if cred.CredentialBlobSize == 0 || cred.CredentialBlob.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                    .to_vec()
            }
        };
        unsafe { CredFree(cred_ptr.cast()) };
        Ok(Some(result))
    }

    #[cfg(windows)]
    pub fn delete(target: &str) -> io::Result<()> {
        use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
        use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};

        let target_wide = wide_null(target);
        let ok = unsafe { CredDeleteW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn list_targets(filter: &str) -> io::Result<Vec<String>> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{ERROR_INVALID_FLAGS, ERROR_NOT_FOUND};
        use windows_sys::Win32::Security::Credentials::{CREDENTIALW, CredEnumerateW, CredFree};

        const ERROR_BAD_ARGUMENTS_CODE: i32 = 1008;

        let pattern = if filter.is_empty() || filter.ends_with('*') {
            filter.to_owned()
        } else {
            format!("{filter}*")
        };
        let filter_wide = wide_null(&pattern);
        let filter_ptr = if pattern.is_empty() {
            ptr::null()
        } else {
            filter_wide.as_ptr()
        };

        let mut count: u32 = 0;
        let mut creds_ptr: *mut *mut CREDENTIALW = ptr::null_mut();
        let ok = unsafe { CredEnumerateW(filter_ptr, 0, &mut count, &mut creds_ptr) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.raw_os_error(),
                Some(code)
                    if code == ERROR_NOT_FOUND as i32
                        || code == ERROR_INVALID_FLAGS as i32
                        || code == ERROR_BAD_ARGUMENTS_CODE
            ) {
                return Ok(Vec::new());
            }
            return Err(err);
        }

        let mut targets = Vec::with_capacity(count as usize);
        unsafe {
            let items = std::slice::from_raw_parts(creds_ptr, count as usize);
            for &item_ptr in items {
                if !item_ptr.is_null() {
                    let cred = &*item_ptr;
                    if !cred.TargetName.is_null() {
                        targets.push(wide_ptr_to_string(cred.TargetName));
                    }
                }
            }
            CredFree(creds_ptr.cast());
        }
        Ok(targets)
    }

    #[cfg(not(windows))]
    pub fn write(_target: &str, _user_name: &str, _secret: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Credential Manager disponivel apenas no Windows.",
        ))
    }

    #[cfg(not(windows))]
    pub fn read(_target: &str) -> io::Result<Option<Vec<u8>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Credential Manager disponivel apenas no Windows.",
        ))
    }

    #[cfg(not(windows))]
    pub fn delete(_target: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Credential Manager disponivel apenas no Windows.",
        ))
    }

    #[cfg(not(windows))]
    pub fn list_targets(_filter: &str) -> io::Result<Vec<String>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Credential Manager disponivel apenas no Windows.",
        ))
    }
}

#[derive(Default)]
pub struct WindowsCredentialStore;

impl CredentialStore for WindowsCredentialStore {
    fn write(&self, target: &str, user_name: &str, secret: &[u8]) -> io::Result<()> {
        CredentialManagerApi::write(target, user_name, secret)
    }

    fn read(&self, target: &str) -> io::Result<Option<Vec<u8>>> {
        CredentialManagerApi::read(target)
    }

    fn delete(&self, target: &str) -> io::Result<()> {
        CredentialManagerApi::delete(target)
    }

    fn list_targets(&self, filter: &str) -> io::Result<Vec<String>> {
        CredentialManagerApi::list_targets(filter)
    }
}

#[cfg(windows)]
pub(crate) fn wide_null(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
pub(crate) unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
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
