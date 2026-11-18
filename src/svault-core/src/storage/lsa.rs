pub struct LsaRights;

impl LsaRights {
    pub const SE_SERVICE_LOGON_RIGHT: &'static str = "SeServiceLogonRight";
    pub const SE_DENY_INTERACTIVE_LOGON_RIGHT: &'static str = "SeDenyInteractiveLogonRight";
    pub const SE_DENY_REMOTE_INTERACTIVE_LOGON_RIGHT: &'static str =
        "SeDenyRemoteInteractiveLogonRight";
    pub const SE_DENY_NETWORK_LOGON_RIGHT: &'static str = "SeDenyNetworkLogonRight";
    pub const SE_BATCH_LOGON_RIGHT: &'static str = "SeBatchLogonRight";

    #[cfg(windows)]
    pub fn resolve_account_sid(account_name: &str) -> Result<String, String> {
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

        use crate::storage::credman::{wide_null, wide_ptr_to_string};

        let name_wide = wide_null(account_name);
        let mut sid_size: u32 = 0;
        let mut domain_size: u32 = 0;
        let mut sid_use: SID_NAME_USE = 0;

        unsafe {
            LookupAccountNameW(
                ptr::null(),
                name_wide.as_ptr(),
                ptr::null_mut(),
                &mut sid_size,
                ptr::null_mut(),
                &mut domain_size,
                &mut sid_use,
            );
        }
        if sid_size == 0 {
            return Err(format!("Nao foi possivel resolver a conta {account_name}."));
        }

        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];
        let ok = unsafe {
            LookupAccountNameW(
                ptr::null(),
                name_wide.as_ptr(),
                sid_buf.as_mut_ptr().cast(),
                &mut sid_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_use,
            )
        };
        if ok == 0 {
            return Err(format!("Nao foi possivel resolver a conta {account_name}."));
        }

        let mut str_ptr: *mut u16 = ptr::null_mut();
        let converted = unsafe { ConvertSidToStringSidW(sid_buf.as_mut_ptr().cast(), &mut str_ptr) };
        if converted == 0 || str_ptr.is_null() {
            return Err(format!("Nao foi possivel converter o SID de {account_name}."));
        }

        let sid_str = unsafe { wide_ptr_to_string(str_ptr) };
        unsafe { LocalFree(str_ptr.cast()) };
        Ok(sid_str)
    }

    #[cfg(not(windows))]
    pub fn resolve_account_sid(_account_name: &str) -> Result<String, String> {
        Err("Resolucao de conta Windows disponivel apenas no Windows.".to_owned())
    }

    pub fn grant(account_sid: &str, rights: &[&str]) -> Result<(), String> {
        Self::apply(account_sid, rights, false)
    }

    pub fn revoke(account_sid: &str, rights: &[&str]) -> Result<(), String> {
        Self::apply(account_sid, rights, true)
    }

    #[cfg(windows)]
    fn apply(account_sid: &str, rights: &[&str], remove: bool) -> Result<(), String> {
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authentication::Identity::{
            LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
            LsaNtStatusToWinError, LsaOpenPolicy, LsaRemoveAccountRights,
        };
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

        use crate::storage::credman::wide_null;

        const POLICY_ALL_ACCESS: u32 = 0x0008_F0FF;

        if rights.is_empty() {
            return Ok(());
        }

        enable_privilege("SeSecurityPrivilege");
        enable_privilege("SeTakeOwnershipPrivilege");

        let sid_wide = wide_null(account_sid);
        let mut sid_ptr = ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid_ptr) };
        if ok == 0 || sid_ptr.is_null() {
            return Err(format!("SID invalido: {account_sid}"));
        }

        let attributes = LSA_OBJECT_ATTRIBUTES {
            Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };

        let mut policy: isize = 0;
        let status = unsafe { LsaOpenPolicy(ptr::null(), &attributes, POLICY_ALL_ACCESS, &mut policy) };
        if status != 0 {
            unsafe { LocalFree(sid_ptr) };
            let win_err = unsafe { LsaNtStatusToWinError(status) };
            return Err(format!(
                "LsaOpenPolicy falhou: NTSTATUS 0x{:08X} (win32 {})",
                status as u32, win_err
            ));
        }

        let mut wide_buffers: Vec<Vec<u16>> = rights.iter().map(|r| wide_null(r)).collect();
        let unicode_strings: Vec<LSA_UNICODE_STRING> = wide_buffers
            .iter_mut()
            .map(|buf| {
                let char_len = buf.len().saturating_sub(1);
                LSA_UNICODE_STRING {
                    Length: (char_len * 2) as u16,
                    MaximumLength: (buf.len() * 2) as u16,
                    Buffer: buf.as_mut_ptr(),
                }
            })
            .collect();

        let status = unsafe {
            if remove {
                LsaRemoveAccountRights(
                    policy,
                    sid_ptr,
                    false,
                    unicode_strings.as_ptr(),
                    unicode_strings.len() as u32,
                )
            } else {
                LsaAddAccountRights(
                    policy,
                    sid_ptr,
                    unicode_strings.as_ptr(),
                    unicode_strings.len() as u32,
                )
            }
        };

        unsafe {
            LsaClose(policy);
            LocalFree(sid_ptr);
        }

        if status != 0 {
            let win_err = unsafe { LsaNtStatusToWinError(status) };
            let fn_name = if remove {
                "LsaRemoveAccountRights"
            } else {
                "LsaAddAccountRights"
            };
            return Err(format!(
                "{fn_name} falhou: NTSTATUS 0x{:08X} (win32 {})",
                status as u32, win_err
            ));
        }

        Ok(())
    }

    #[cfg(not(windows))]
    fn apply(_account_sid: &str, _rights: &[&str], _remove: bool) -> Result<(), String> {
        Err("API LSA disponivel apenas no Windows.".to_owned())
    }
}

#[cfg(windows)]
fn enable_privilege(name: &str) {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LUID};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::storage::credman::wide_null;

    let mut token = ptr::null_mut();
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if opened == 0 || token.is_null() {
        return;
    }

    let name_wide = wide_null(name);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    if unsafe { LookupPrivilegeValueW(ptr::null(), name_wide.as_ptr(), &mut luid) } != 0 {
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut());
        }
    }

    unsafe {
        CloseHandle(token);
    }
}
