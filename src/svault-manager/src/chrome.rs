use raw_window_handle::{HasWindowHandle, RawWindowHandle};

#[cfg(windows)]
fn hwnd(window: &slint::Window) -> Option<windows_sys::Win32::Foundation::HWND> {
    let handle = window.window_handle();
    match handle.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(win32) => Some(win32.hwnd.get() as _),
        _ => None,
    }
}

#[cfg(windows)]
pub fn apply_dark_title_bar(window: &slint::Window) {
    use windows_sys::Win32::Graphics::Dwm::{
        DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
        DwmSetWindowAttribute,
    };

    let Some(hwnd) = hwnd(window) else { return };
    let dark: i32 = 1;
    let caption: u32 = 0x0018_1311;
    let text: u32 = 0x00f0_ebe9;
    unsafe {
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE as _, (&dark as *const i32).cast(), 4);
        DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR as _, (&caption as *const u32).cast(), 4);
        DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR as _, (&caption as *const u32).cast(), 4);
        DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR as _, (&text as *const u32).cast(), 4);
    }
}

#[cfg(windows)]
pub fn flash_taskbar(window: &slint::Window) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{FLASHW_TIMERNOFG, FLASHW_TRAY, FLASHWINFO, FlashWindowEx};

    let Some(hwnd) = hwnd(window) else { return };
    let info = FLASHWINFO {
        cbSize: size_of::<FLASHWINFO>() as u32,
        hwnd,
        dwFlags: FLASHW_TRAY | FLASHW_TIMERNOFG,
        uCount: 0,
        dwTimeout: 0,
    };
    unsafe {
        FlashWindowEx(&info);
    }
}

#[cfg(not(windows))]
pub fn apply_dark_title_bar(_window: &slint::Window) {}

#[cfg(not(windows))]
pub fn flash_taskbar(_window: &slint::Window) {}
