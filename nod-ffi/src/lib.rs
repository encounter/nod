//! C API for reading GameCube and Wii disc images.
//!
//! # Safety
//!
//! All `unsafe extern "C"` functions in this crate require that pointer arguments
//! are either null (checked and handled gracefully) or valid, aligned, and point
//! to the expected types. Handles must originate from the corresponding `nod_*_open*`
//! function and must not be used after being freed with `nod_free`.
#![allow(clippy::missing_safety_doc)]

mod error;
mod handle;
mod stream;
mod types;

use std::{
    ffi::{CStr, CString, c_char, c_void},
    io::{BufRead, Read, Seek, SeekFrom},
};

use nod::{
    common::PartitionKind,
    disc::{DiscHeader, fst::Fst},
    read::{DiscOptions, DiscReader, PartitionOptions},
};

use crate::{
    error::{NodResult, clear_last_error, set_error_from_nod, set_last_error},
    handle::{NodHandle, NodHandleInner},
    stream::FfiDiscStream,
    types::{
        NOD_FST_STOP, NodDiscHeader, NodDiscMeta, NodDiscOptions, NodDiscStream, NodFstCallback,
        NodNodeKind, NodPartitionInfo, NodPartitionMeta, NodPartitionOptions,
    },
};

/// Validate a handle pointer, returning `$err` if null or freed.
macro_rules! check_handle {
    ($ptr:expr, $err:expr) => {{
        if $ptr.is_null() {
            set_last_error("null handle");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        if !$ptr.is_aligned() {
            set_last_error("unaligned handle pointer");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        let h = unsafe { &*$ptr };
        if !h.is_valid() {
            set_last_error("use after free");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        h
    }};
}

/// Validate a mutable handle pointer, returning `$err` if null or freed.
macro_rules! check_handle_mut {
    ($ptr:expr, $err:expr) => {{
        if $ptr.is_null() {
            set_last_error("null handle");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        if !$ptr.is_aligned() {
            set_last_error("unaligned handle pointer");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        let h = unsafe { &mut *$ptr };
        if !h.is_valid() {
            set_last_error("use after free");
            #[allow(clippy::unused_unit)]
            return $err;
        }
        h
    }};
}

/// Returns a pointer to the last error message, or null if no error has occurred.
///
/// The returned string is valid until the next `nod_*` call on the same thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_error_message() -> *const c_char { error::last_error_message() }

/// Opens a disc image from a file path.
///
/// `options` may be null to use defaults.
///
/// On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
/// The handle must be freed with `nod_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_open(
    path: *const c_char,
    options: *const NodDiscOptions,
    out: *mut *mut NodHandle,
) -> NodResult {
    clear_last_error();
    if path.is_null() || out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let path = unsafe { CStr::from_ptr(path) };
    let path = match path.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in path: {e}"));
            return NodResult::ErrOther;
        }
    };
    let options = if options.is_null() {
        DiscOptions::default()
    } else {
        DiscOptions::from(unsafe { &*options })
    };
    match DiscReader::new(path, &options) {
        Ok(disc) => {
            let handle = Box::new(NodHandle::new(NodHandleInner::Disc(disc)));
            unsafe { *out = Box::into_raw(handle) };
            NodResult::Ok
        }
        Err(e) => set_error_from_nod(e),
    }
}

/// Opens a disc image from a callback-backed stream.
///
/// `stream` callbacks must be valid and non-null.
/// `options` may be null to use defaults.
///
/// On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
/// The handle must be freed with `nod_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_open_stream(
    stream: *const NodDiscStream,
    options: *const NodDiscOptions,
    out: *mut *mut NodHandle,
) -> NodResult {
    clear_last_error();
    if stream.is_null() || out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !stream.is_aligned() || !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let options = if options.is_null() {
        DiscOptions::default()
    } else {
        DiscOptions::from(unsafe { &*options })
    };
    let stream = FfiDiscStream::new(unsafe { &*stream });
    match DiscReader::new_stream(Box::new(stream), &options) {
        Ok(disc) => {
            let handle = Box::new(NodHandle::new(NodHandleInner::Disc(disc)));
            unsafe { *out = Box::into_raw(handle) };
            NodResult::Ok
        }
        Err(e) => set_error_from_nod(e),
    }
}

/// Opens a partition by index from a disc handle.
///
/// `disc` must be a handle returned by `nod_disc_open`.
/// `options` may be null to use defaults.
///
/// **GameCube**: `index` must always be 0.
///
/// On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
/// The partition handle must be freed with `nod_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_open_partition(
    disc: *mut NodHandle,
    index: u32,
    options: *const NodPartitionOptions,
    out: *mut *mut NodHandle,
) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let disc = check_handle!(disc, NodResult::ErrInvalidHandle);
    let disc_reader = match &disc.inner {
        NodHandleInner::Disc(d) => d,
        _ => {
            set_last_error("handle is not a disc");
            return NodResult::ErrInvalidHandle;
        }
    };
    let opts = if options.is_null() {
        PartitionOptions::default()
    } else {
        PartitionOptions::from(unsafe { &*options })
    };
    let mut reader = match disc_reader.open_partition(index as usize, &opts) {
        Ok(r) => r,
        Err(e) => return set_error_from_nod(e),
    };
    let meta = match reader.meta() {
        Ok(m) => m,
        Err(e) => return set_error_from_nod(e),
    };
    // Ensure the reader is at position 0
    if let Err(e) = reader.seek(SeekFrom::Start(0)) {
        set_last_error(e.to_string());
        return NodResult::ErrIo;
    }
    let handle = Box::new(NodHandle::new(NodHandleInner::Partition { reader, meta }));
    unsafe { *out = Box::into_raw(handle) };
    NodResult::Ok
}

/// Opens a partition by kind from a disc handle.
///
/// Searches for the first partition matching `kind` (0 = Data, 1 = Update, 2 = Channel).
/// `options` may be null to use defaults.
///
/// **GameCube**: `kind` must always be `NOD_PARTITION_KIND_DATA`.
///
/// On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
/// The partition handle must be freed with `nod_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_open_partition_kind(
    disc: *mut NodHandle,
    kind: u32,
    options: *const NodPartitionOptions,
    out: *mut *mut NodHandle,
) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let disc = check_handle!(disc, NodResult::ErrInvalidHandle);
    let disc_reader = match &disc.inner {
        NodHandleInner::Disc(d) => d,
        _ => {
            set_last_error("handle is not a disc");
            return NodResult::ErrInvalidHandle;
        }
    };
    let opts = if options.is_null() {
        PartitionOptions::default()
    } else {
        PartitionOptions::from(unsafe { &*options })
    };
    let partition_kind = PartitionKind::from(kind);
    let mut reader = match disc_reader.open_partition_kind(partition_kind, &opts) {
        Ok(r) => r,
        Err(e) => return set_error_from_nod(e),
    };
    let meta = match reader.meta() {
        Ok(m) => m,
        Err(e) => return set_error_from_nod(e),
    };
    if let Err(e) = reader.seek(SeekFrom::Start(0)) {
        set_last_error(e.to_string());
        return NodResult::ErrIo;
    }
    let handle = Box::new(NodHandle::new(NodHandleInner::Partition { reader, meta }));
    unsafe { *out = Box::into_raw(handle) };
    NodResult::Ok
}

/// Opens a file from a partition handle by FST node index.
///
/// `partition` must be a handle returned by `nod_disc_open_partition` or
/// `nod_disc_open_partition_kind`.
/// On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
/// The file handle must be freed with `nod_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_partition_open_file(
    partition: *mut NodHandle,
    fst_index: u32,
    out: *mut *mut NodHandle,
) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let partition = check_handle!(partition, NodResult::ErrInvalidHandle);
    let (reader, meta) = match &partition.inner {
        NodHandleInner::Partition { reader, meta } => (reader, meta),
        _ => {
            set_last_error("handle is not a partition");
            return NodResult::ErrInvalidHandle;
        }
    };
    let fst = match Fst::new(&meta.raw_fst) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(e);
            return NodResult::ErrFormat;
        }
    };
    let node = match fst.nodes.get(fst_index as usize) {
        Some(n) => *n,
        None => {
            set_last_error(format!(
                "FST index {} out of range (total: {})",
                fst_index,
                fst.nodes.len()
            ));
            return NodResult::ErrNotFound;
        }
    };
    if !node.is_file() {
        set_last_error("node is not a file");
        return NodResult::ErrFormat;
    }
    let file_reader = match reader.clone().into_open_file(node) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(e.to_string());
            return NodResult::ErrIo;
        }
    };
    let handle = Box::new(NodHandle::new(NodHandleInner::File(file_reader)));
    unsafe { *out = Box::into_raw(handle) };
    NodResult::Ok
}

/// Frees a handle returned by any `nod_*_open*` function.
///
/// Passing null is a no-op. After this call, the handle is invalid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_free(handle: *mut NodHandle) {
    if !handle.is_null() && handle.is_aligned() && unsafe { &*handle }.is_valid() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Reads up to `len` bytes from a handle into `buf`.
///
/// This function may return fewer than `len` bytes even before end-of-stream.
/// Callers that need an exact byte count must loop until the buffer is filled
/// or the function returns 0 (end-of-stream) / -1 (error).
///
/// Returns the number of bytes read, or -1 on error.
/// Returns 0 at end-of-stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_read(handle: *mut NodHandle, buf: *mut u8, len: usize) -> i64 {
    clear_last_error();
    if buf.is_null() {
        set_last_error("null pointer argument");
        return -1;
    }
    let handle = check_handle_mut!(handle, -1);
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match handle.inner.read(slice) {
        Ok(n) => n as i64,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Seeks a handle to a new position.
///
/// `whence`: 0 = from start, 1 = from current, 2 = from end.
/// Returns the new absolute position, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_seek(handle: *mut NodHandle, offset: i64, whence: i32) -> i64 {
    clear_last_error();
    let handle = check_handle_mut!(handle, -1);
    let pos = match whence {
        0 => SeekFrom::Start(offset as u64),
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        _ => {
            set_last_error(format!("invalid whence value: {whence}"));
            return -1;
        }
    };
    match handle.inner.seek(pos) {
        Ok(n) => n as i64,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Returns a pointer to the internal buffer and its length for zero-copy reads.
///
/// On success, `*out_len` is set to the number of available bytes and a pointer
/// to the buffer is returned. Returns null on error or end-of-stream.
/// Call `nod_buf_consume` after processing the data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_buf_read(
    handle: *mut NodHandle,
    out_len: *mut usize,
) -> *const c_void {
    clear_last_error();
    if out_len.is_null() {
        set_last_error("null pointer argument");
        return std::ptr::null();
    }
    if !out_len.is_aligned() {
        set_last_error("unaligned pointer argument");
        return std::ptr::null();
    }
    let handle = check_handle_mut!(handle, std::ptr::null());
    match handle.inner.fill_buf() {
        Ok(buf) => {
            unsafe { *out_len = buf.len() };
            if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() as *const c_void }
        }
        Err(e) => {
            set_last_error(e.to_string());
            unsafe { *out_len = 0 };
            std::ptr::null()
        }
    }
}

/// Consumes `n` bytes from the internal buffer after a `nod_buf_read` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_buf_consume(handle: *mut NodHandle, n: usize) {
    if handle.is_null() {
        return;
    }
    let handle = unsafe { &mut *handle };
    if !handle.is_valid() {
        set_last_error("use after free");
        return;
    }
    handle.inner.consume(n);
}

/// Copies the disc header into the provided struct.
///
/// `disc` must be a disc handle. `out` must point to a valid `NodDiscHeader`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_header(
    disc: *const NodHandle,
    out: *mut NodDiscHeader,
) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let disc = check_handle!(disc, NodResult::ErrInvalidHandle);
    let disc_reader = match &disc.inner {
        NodHandleInner::Disc(d) => d,
        _ => {
            set_last_error("handle is not a disc");
            return NodResult::ErrInvalidHandle;
        }
    };
    // Compile-time assertion to ensure `NodDiscHeader` has the same size as `DiscHeader`.
    const _: [(); std::mem::size_of::<NodDiscHeader>()] = [(); std::mem::size_of::<DiscHeader>()];
    unsafe {
        std::ptr::copy_nonoverlapping(
            disc_reader.header() as *const DiscHeader as *const u8,
            out as *mut u8,
            std::mem::size_of::<NodDiscHeader>(),
        );
    }
    NodResult::Ok
}

/// Copies the disc metadata into the provided struct.
///
/// `disc` must be a disc handle. `out` must point to a valid `NodDiscMeta`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_meta(disc: *const NodHandle, out: *mut NodDiscMeta) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let disc = check_handle!(disc, NodResult::ErrInvalidHandle);
    let disc_reader = match &disc.inner {
        NodHandleInner::Disc(d) => d,
        _ => {
            set_last_error("handle is not a disc");
            return NodResult::ErrInvalidHandle;
        }
    };
    unsafe { *out = NodDiscMeta::from(&disc_reader.meta()) };
    NodResult::Ok
}

/// Returns the disc size in bytes.
///
/// `disc` must be a disc handle. Returns 0 if the handle is invalid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_size(disc: *const NodHandle) -> u64 {
    let disc = check_handle!(disc, 0);
    match &disc.inner {
        NodHandleInner::Disc(d) => d.disc_size(),
        _ => 0,
    }
}

/// Copies partition info into a caller-provided array.
///
/// `out` is a pointer to an array of `NodPartitionInfo` with capacity `cap`.
/// Returns the total number of partitions (which may exceed `cap`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_disc_partitions(
    disc: *const NodHandle,
    out: *mut NodPartitionInfo,
    cap: usize,
) -> usize {
    let disc = check_handle!(disc, 0);
    let disc_reader = match &disc.inner {
        NodHandleInner::Disc(d) => d,
        _ => return 0,
    };
    let partitions = disc_reader.partitions();
    let copy_count = cap.min(partitions.len());
    if !out.is_null() && out.is_aligned() && copy_count > 0 {
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out, copy_count) };
        for (i, p) in partitions.iter().take(copy_count).enumerate() {
            out_slice[i] = NodPartitionInfo::from(p);
        }
    }
    partitions.len()
}

/// Returns whether the partition is from a Wii disc.
///
/// `partition` must be a partition handle. Returns false if the handle is invalid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_partition_is_wii(partition: *const NodHandle) -> bool {
    let partition = check_handle!(partition, false);
    match &partition.inner {
        NodHandleInner::Partition { reader, .. } => reader.is_wii(),
        _ => false,
    }
}

/// Copies partition metadata blob pointers and sizes into the provided struct.
///
/// `partition` must be a partition handle. `out` must point to a valid
/// `NodPartitionMeta`. Returned pointers are borrowed and remain valid while
/// the partition handle is alive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_partition_meta(
    partition: *const NodHandle,
    out: *mut NodPartitionMeta,
) -> NodResult {
    clear_last_error();
    if out.is_null() {
        set_last_error("null pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    if !out.is_aligned() {
        set_last_error("unaligned pointer argument");
        return NodResult::ErrInvalidHandle;
    }
    let partition = check_handle!(partition, NodResult::ErrInvalidHandle);
    let meta = match &partition.inner {
        NodHandleInner::Partition { meta, .. } => meta,
        _ => {
            set_last_error("handle is not a partition");
            return NodResult::ErrInvalidHandle;
        }
    };
    unsafe { *out = NodPartitionMeta::from(meta) };
    NodResult::Ok
}

/// Finds a file in the partition's file system table by path.
///
/// If found, `*out_kind` and `*out_length` are set and the FST node index is returned.
/// Returns `NOD_FST_STOP` (`UINT32_MAX`) if the file is not found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_partition_find_file(
    partition: *const NodHandle,
    path: *const c_char,
    out_kind: *mut NodNodeKind,
    out_length: *mut u32,
) -> u32 {
    clear_last_error();
    if path.is_null() {
        set_last_error("null pointer argument");
        return NOD_FST_STOP;
    }
    let partition = check_handle!(partition, NOD_FST_STOP);
    let meta = match &partition.inner {
        NodHandleInner::Partition { meta, .. } => meta,
        _ => {
            set_last_error("handle is not a partition");
            return NOD_FST_STOP;
        }
    };
    let fst = match Fst::new(&meta.raw_fst) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(e);
            return NOD_FST_STOP;
        }
    };
    let path = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in path: {e}"));
            return NOD_FST_STOP;
        }
    };
    match fst.find(path) {
        Some((idx, node)) => {
            if !out_kind.is_null() && out_kind.is_aligned() {
                unsafe { *out_kind = NodNodeKind::from(node.kind()) };
            }
            if !out_length.is_null() && out_length.is_aligned() {
                unsafe { *out_length = node.length() };
            }
            idx as u32
        }
        None => NOD_FST_STOP,
    }
}

/// Iterates over all entries in the partition's file system table.
///
/// The callback receives each node's index, kind, name, size, and user data.
/// Return the next index to visit from the callback, or `NOD_FST_STOP` to stop.
/// For normal sequential iteration, return `index + 1`.
/// For directories, return `size` (which is the child-end index) to skip the subtree.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nod_partition_iterate_fst(
    partition: *const NodHandle,
    callback: NodFstCallback,
    user_data: *mut c_void,
) {
    clear_last_error();
    let partition = check_handle!(partition, ());
    let meta = match &partition.inner {
        NodHandleInner::Partition { meta, .. } => meta,
        _ => {
            set_last_error("handle is not a partition");
            return;
        }
    };
    let fst = match Fst::new(&meta.raw_fst) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(e);
            return;
        }
    };

    let mut idx: usize = 1; // skip root node
    while let Some(node) = fst.nodes.get(idx).copied() {
        let name = fst.get_name(node).unwrap_or("<invalid>".into());
        let name_c = CString::new(name.as_ref()).unwrap_or_default();
        let kind = NodNodeKind::from(node.kind());
        idx = unsafe { callback(idx as u32, kind, name_c.as_ptr(), node.length(), user_data) }
            as usize;
    }
}
