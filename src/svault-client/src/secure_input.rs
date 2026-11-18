use std::io::{self, BufRead, Write};

use zeroize::Zeroizing;

/// Reads secrets from the console without echo and without ever touching the clipboard.
pub struct SecureInput;

impl SecureInput {
    pub fn read_secret(prompt: &str) -> io::Result<Zeroizing<String>> {
        print!("{prompt}");
        io::stdout().flush()?;

        #[cfg(windows)]
        {
            if let Some(secret) = read_console_secret_windows()? {
                return Ok(secret);
            }
        }

        // Fallback when stdin is redirected (non-interactive test pipes).
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        if line.starts_with('\u{feff}') {
            line.remove(0);
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        println!();
        Ok(line)
    }

    pub fn read_line(prompt: &str) -> io::Result<String> {
        print!("{prompt}");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Ok(line.trim().to_owned())
    }
}

#[cfg(windows)]
fn read_console_secret_windows() -> io::Result<Option<Zeroizing<String>>> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW,
        STD_INPUT_HANDLE,
    };

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(None);
    }

    let mut mode: u32 = 0;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return Ok(None);
    }

    let mut builder = Zeroizing::new(String::new());
    let mut high_surrogate: Option<u16> = None;

    loop {
        let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
        let mut read: u32 = 0;
        let ok = unsafe { ReadConsoleInputW(handle, &mut record, 1, &mut read) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 || u32::from(record.EventType) != KEY_EVENT {
            continue;
        }

        let key = unsafe { record.Event.KeyEvent };
        if key.bKeyDown == 0 {
            continue;
        }

        const VK_RETURN: u16 = 0x0D;
        const VK_BACK: u16 = 0x08;
        const VK_ESCAPE: u16 = 0x1B;

        let u_char = unsafe { key.uChar.UnicodeChar };

        if key.wVirtualKeyCode == VK_RETURN || u_char == 0x0D || u_char == 0x0A {
            println!();
            io::stdout().flush()?;
            return Ok(Some(builder));
        }

        if u_char == 0x03 {
            // Ctrl+C
            println!();
            std::process::exit(130);
        }

        if key.wVirtualKeyCode == VK_ESCAPE || u_char == 0x1B {
            builder.clear();
            println!();
            io::stdout().flush()?;
            return Ok(Some(Zeroizing::new(String::new())));
        }

        if key.wVirtualKeyCode == VK_BACK || u_char == 0x08 {
            if builder.pop().is_some() {
                print!("\x08 \x08");
                io::stdout().flush()?;
            }
            continue;
        }

        if u_char == 0 {
            continue;
        }

        if (0xD800..=0xDBFF).contains(&u_char) {
            high_surrogate = Some(u_char);
            continue;
        }

        let decoded = if let Some(high) = high_surrogate.take() {
            char::decode_utf16([high, u_char]).next().and_then(Result::ok)
        } else {
            char::from_u32(u32::from(u_char))
        };

        if let Some(ch) = decoded
            && !ch.is_control()
        {
            builder.push(ch);
            print!("*");
            io::stdout().flush()?;
        }
    }
}
