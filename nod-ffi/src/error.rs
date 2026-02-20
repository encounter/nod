use std::{
    cell::RefCell,
    ffi::{CString, c_char},
};

/// Result codes returned by nod FFI functions.
#[repr(C)]
pub enum NodResult {
    /// Operation succeeded.
    Ok,
    /// An I/O error occurred.
    ErrIo,
    /// The disc format is invalid or unsupported.
    ErrFormat,
    /// The requested item was not found.
    ErrNotFound,
    /// The provided handle is null or of the wrong type.
    ErrInvalidHandle,
    /// An unclassified error occurred.
    ErrOther,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub(crate) fn set_last_error(msg: impl Into<String>) {
    let msg = msg.into();
    let c = CString::new(msg).unwrap_or_else(|_| c"(error contained null byte)".to_owned());
    LAST_ERROR.set(Some(c));
}

pub(crate) fn clear_last_error() { LAST_ERROR.set(None); }

/// Returns a pointer to the last error message, or null if no error.
///
/// The pointer is valid until the next FFI call on the same thread.
pub(crate) fn last_error_message() -> *const c_char {
    LAST_ERROR.with(|e| {
        let borrow = e.borrow();
        match borrow.as_ref() {
            Some(c) => c.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

pub(crate) fn set_error_from_nod(err: nod::Error) -> NodResult {
    set_last_error(err.to_string());
    match &err {
        nod::Error::Io(_, _) => NodResult::ErrIo,
        nod::Error::DiscFormat(_) => NodResult::ErrFormat,
        nod::Error::Other(_) => NodResult::ErrOther,
    }
}
