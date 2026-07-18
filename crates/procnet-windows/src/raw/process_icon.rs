use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::{ptr, slice};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, HBITMAP, HBRUSH, HDC, SelectObject,
};
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGetFileInfoW};
use windows::Win32::UI::WindowsAndMessaging::{DI_NORMAL, DestroyIcon, DrawIconEx, HICON};
use windows::core::PCWSTR;

const ICON_SIZE: u32 = 32;
const ICON_SIZE_USIZE: usize = 32;

pub(crate) struct NativeIcon {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) rgba: Vec<u8>,
}

struct IconGuard(HICON);

impl Drop for IconGuard {
    fn drop(&mut self) {
        // SAFETY: SHGetFileInfoW returned this owned icon handle, and this guard drops it once.
        unsafe {
            let _ = DestroyIcon(self.0);
        }
    }
}

struct DcGuard(HDC);

impl Drop for DcGuard {
    fn drop(&mut self) {
        // SAFETY: CreateCompatibleDC returned this memory DC, and this guard drops it once.
        unsafe {
            let _ = DeleteDC(self.0);
        }
    }
}

struct BitmapGuard(HBITMAP);

impl Drop for BitmapGuard {
    fn drop(&mut self) {
        // SAFETY: CreateDIBSection returned this bitmap, it is deselected before guard drop.
        unsafe {
            let _ = DeleteObject(self.0);
        }
    }
}

pub(crate) fn load_icon(path: &Path) -> Result<Option<NativeIcon>, String> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut file_info = SHFILEINFOW::default();
    let file_info_size = u32::try_from(size_of::<SHFILEINFOW>())
        .map_err(|_| "SHFILEINFOW size does not fit u32".to_owned())?;
    // SAFETY: `wide` is NUL-terminated and remains alive; `file_info` points to its exact type and
    // the supplied size is computed from that type.
    let result = unsafe {
        SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&raw mut file_info),
            file_info_size,
            SHGFI_ICON | SHGFI_SMALLICON,
        )
    };
    if result == 0 || file_info.hIcon.0 == 0 {
        return Ok(None);
    }
    let icon = IconGuard(file_info.hIcon);
    render_icon(&icon).map(Some)
}

fn render_icon(icon: &IconGuard) -> Result<NativeIcon, String> {
    // SAFETY: A null source HDC is permitted when creating a memory device context.
    let dc = DcGuard(unsafe { CreateCompatibleDC(None) });
    if dc.0.0 == 0 {
        return Err("CreateCompatibleDC failed".to_owned());
    }
    let header_size = u32::try_from(size_of::<BITMAPINFOHEADER>())
        .map_err(|_| "BITMAPINFOHEADER size does not fit u32".to_owned())?;
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: header_size,
            biWidth: i32::try_from(ICON_SIZE).unwrap_or(i32::MAX),
            biHeight: -i32::try_from(ICON_SIZE).unwrap_or(i32::MAX),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits: *mut c_void = ptr::null_mut();
    // SAFETY: `info` is initialized for a top-down 32-bit DIB and `bits` is a valid out pointer.
    let bitmap = BitmapGuard(unsafe {
        CreateDIBSection(
            dc.0,
            &raw const info,
            DIB_RGB_COLORS,
            &raw mut bits,
            HANDLE::default(),
            0,
        )
        .map_err(|error| format!("CreateDIBSection failed: {error}"))?
    });
    if bits.is_null() {
        return Err("CreateDIBSection returned a null pixel buffer".to_owned());
    }
    // SAFETY: The DIB owns exactly ICON_SIZE * ICON_SIZE * 4 writable bytes for its lifetime.
    unsafe {
        ptr::write_bytes(bits, 0, pixel_buffer_len());
    }
    // SAFETY: Both handles are live and compatible; the returned object is restored below.
    let previous = unsafe { SelectObject(dc.0, bitmap.0) };
    if previous.0 == 0 || previous.0 == -1 {
        return Err("SelectObject failed".to_owned());
    }
    // SAFETY: The selected DIB, memory DC, and icon handle remain live for the draw call.
    let draw_result = unsafe {
        DrawIconEx(
            dc.0,
            0,
            0,
            icon.0,
            i32::try_from(ICON_SIZE).unwrap_or(i32::MAX),
            i32::try_from(ICON_SIZE).unwrap_or(i32::MAX),
            0,
            HBRUSH::default(),
            DI_NORMAL,
        )
    };
    // SAFETY: `previous` came from this DC's successful SelectObject call.
    unsafe {
        let _ = SelectObject(dc.0, previous);
    }
    draw_result.map_err(|error| format!("DrawIconEx failed: {error}"))?;
    // SAFETY: `bits` remains valid until `bitmap` drops and its exact initialized length is known.
    let bgra = unsafe { slice::from_raw_parts(bits.cast::<u8>(), pixel_buffer_len()) };
    let mut rgba = Vec::with_capacity(bgra.len());
    let has_alpha = bgra.chunks_exact(4).any(|pixel| pixel[3] != 0);
    for pixel in bgra.chunks_exact(4) {
        rgba.extend_from_slice(&[
            pixel[2],
            pixel[1],
            pixel[0],
            if has_alpha { pixel[3] } else { 255 },
        ]);
    }
    Ok(NativeIcon {
        width: ICON_SIZE,
        height: ICON_SIZE,
        rgba,
    })
}

const fn pixel_buffer_len() -> usize {
    ICON_SIZE_USIZE * ICON_SIZE_USIZE * 4
}
