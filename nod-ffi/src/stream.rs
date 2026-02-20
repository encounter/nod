use std::{
    ffi::c_void,
    io::{self, ErrorKind},
    sync::{Arc, Mutex},
};

use nod::read::DiscStream;

use crate::types::{
    NodDiscStream, NodDiscStreamCloseCallback, NodDiscStreamLenCallback,
    NodDiscStreamReadAtCallback,
};

struct FfiDiscStreamInner {
    user_data: usize,
    read_at: NodDiscStreamReadAtCallback,
    stream_len: NodDiscStreamLenCallback,
    close: NodDiscStreamCloseCallback,
}

impl Drop for FfiDiscStreamInner {
    fn drop(&mut self) { unsafe { (self.close)(self.user_data as *mut c_void) } }
}

/// A C-callback-backed stream implementation for `nod::read::DiscStream`.
///
/// Clones share the same callback state and serialize callback invocations.
#[derive(Clone)]
pub(crate) struct FfiDiscStream {
    inner: Arc<Mutex<FfiDiscStreamInner>>,
}

impl FfiDiscStream {
    pub(crate) fn new(stream: &NodDiscStream) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FfiDiscStreamInner {
                user_data: stream.user_data as usize,
                read_at: stream.read_at,
                stream_len: stream.stream_len,
                close: stream.close,
            })),
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, FfiDiscStreamInner>> {
        self.inner.lock().map_err(|_| io::Error::other("NodDiscStream mutex poisoned"))
    }
}

impl DiscStream for FfiDiscStream {
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let mut total = 0usize;
        while total < buf.len() {
            let read_offset = offset.checked_add(total as u64).ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidInput, "NodDiscStream.read_at offset overflow")
            })?;
            let out = &mut buf[total..];
            let result = {
                let inner = self.lock()?;
                unsafe {
                    (inner.read_at)(
                        inner.user_data as *mut c_void,
                        read_offset,
                        out.as_mut_ptr().cast::<c_void>(),
                        out.len(),
                    )
                }
            };
            if result < 0 {
                return Err(io::Error::other("NodDiscStream.read_at callback failed"));
            }
            let read = result as usize;
            if read == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof));
            }
            if read > out.len() {
                return Err(io::Error::other(
                    "NodDiscStream.read_at callback returned more bytes than requested",
                ));
            }
            total += read;
        }
        Ok(())
    }

    fn stream_len(&mut self) -> io::Result<u64> {
        let result = {
            let inner = self.lock()?;
            unsafe { (inner.stream_len)(inner.user_data as *mut c_void) }
        };
        if result < 0 {
            return Err(io::Error::other("NodDiscStream.stream_len callback failed"));
        }
        Ok(result as u64)
    }
}
