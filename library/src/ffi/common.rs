use std::ffi::{CString, c_char};

#[repr(C)]
pub struct DeRecBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct DeRecStatus {
    pub code: i32,
    pub message: *mut c_char,
}

pub(crate) fn ok_status() -> DeRecStatus {
    DeRecStatus {
        code: 0,
        message: std::ptr::null_mut(),
    }
}

pub(crate) fn err_status(msg: impl AsRef<str>) -> DeRecStatus {
    let cstring =
        CString::new(msg.as_ref()).unwrap_or_else(|_| CString::new("internal error").unwrap());

    DeRecStatus {
        code: 1,
        message: cstring.into_raw(),
    }
}

pub(crate) fn empty_buffer() -> DeRecBuffer {
    DeRecBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

pub(crate) fn vec_into_buffer(mut data: Vec<u8>) -> DeRecBuffer {
    let ptr = data.as_mut_ptr();
    let len = data.len();
    std::mem::forget(data);

    DeRecBuffer { ptr, len }
}

#[unsafe(no_mangle)]
pub extern "C" fn derec_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn derec_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(ptr));
    }
}

pub(crate) fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("pairing secret key component too large");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn write_optional_len_prefixed(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            out.push(1);
            write_len_prefixed(out, bytes);
        }
        None => out.push(0),
    }
}

pub(crate) fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn read_exact<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if input.len() < len {
        return Err("unexpected end of input".to_string());
    }

    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

pub(crate) fn read_u8(input: &mut &[u8]) -> Result<u8, String> {
    Ok(read_exact(input, 1)?[0])
}

pub(crate) fn read_u32_le(input: &mut &[u8]) -> Result<u32, String> {
    let bytes = read_exact(input, 4)?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| "failed to read u32".to_string())?;
    Ok(u32::from_le_bytes(array))
}

pub(crate) fn read_len_prefixed_vec(input: &mut &[u8]) -> Result<Vec<u8>, String> {
    let len = read_u32_le(input)? as usize;
    let bytes = read_exact(input, len)?;
    Ok(bytes.to_vec())
}

pub(crate) fn read_optional_len_prefixed_vec(input: &mut &[u8]) -> Result<Option<Vec<u8>>, String> {
    match read_u8(input)? {
        0 => Ok(None),
        1 => Ok(Some(read_len_prefixed_vec(input)?)),
        _ => Err("invalid optional field tag".to_string()),
    }
}
