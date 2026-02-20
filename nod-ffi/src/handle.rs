use std::io::{self, BufRead, Read, Seek};

use nod::read::{DiscReader, OwnedFileReader, PartitionMeta, PartitionReader};

const HANDLE_MAGIC: u32 = 0x4E4F4448; // "NODH"

/// Opaque handle representing a disc, partition, or file reader.
pub struct NodHandle {
    magic: u32,
    pub(crate) inner: NodHandleInner,
}

impl NodHandle {
    pub(crate) fn new(inner: NodHandleInner) -> Self { NodHandle { magic: HANDLE_MAGIC, inner } }

    pub(crate) fn is_valid(&self) -> bool { self.magic == HANDLE_MAGIC }
}

impl Drop for NodHandle {
    fn drop(&mut self) { self.magic = 0; }
}

pub(crate) enum NodHandleInner {
    Disc(DiscReader),
    Partition { reader: Box<dyn PartitionReader>, meta: PartitionMeta },
    File(OwnedFileReader),
}

impl NodHandleInner {
    fn as_read(&mut self) -> &mut dyn Read {
        match self {
            NodHandleInner::Disc(r) => r,
            NodHandleInner::Partition { reader, .. } => reader.as_mut(),
            NodHandleInner::File(r) => r,
        }
    }

    fn as_seek(&mut self) -> &mut dyn Seek {
        match self {
            NodHandleInner::Disc(r) => r,
            NodHandleInner::Partition { reader, .. } => reader.as_mut(),
            NodHandleInner::File(r) => r,
        }
    }

    fn as_bufread(&mut self) -> &mut dyn BufRead {
        match self {
            NodHandleInner::Disc(r) => r,
            NodHandleInner::Partition { reader, .. } => reader.as_mut(),
            NodHandleInner::File(r) => r,
        }
    }
}

impl Read for NodHandleInner {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.as_read().read(buf) }
}

impl BufRead for NodHandleInner {
    fn fill_buf(&mut self) -> io::Result<&[u8]> { self.as_bufread().fill_buf() }

    fn consume(&mut self, n: usize) { self.as_bufread().consume(n); }
}

impl Seek for NodHandleInner {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> { self.as_seek().seek(pos) }
}
