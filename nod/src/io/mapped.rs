use std::{io, path::Path, sync::Arc};

use memmap2::Mmap;

use crate::{util::impl_read_for_bufread, Result, ResultContext};

pub struct MappedFileReader {
    inner: Arc<Mmap>,
    pos: usize,
}

impl Clone for MappedFileReader {
    fn clone(&self) -> Self { Self { inner: self.inner.clone(), pos: 0 } }
}

impl MappedFileReader {
    #[expect(unused)]
    pub fn new(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open file {}", path.display()))?;
        let inner = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to map file {}", path.display()))?;
        Ok(Self { inner: Arc::new(inner), pos: 0 })
    }
}

impl io::BufRead for MappedFileReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos < self.inner.len() {
            Ok(&self.inner[self.pos..])
        } else {
            Ok(&[])
        }
    }

    fn consume(&mut self, amt: usize) { self.pos = self.pos.saturating_add(amt); }
}

impl_read_for_bufread!(MappedFileReader);

impl io::Seek for MappedFileReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let pos = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(pos) => (self.inner.len() as u64).saturating_add_signed(pos),
            io::SeekFrom::Current(off) => (self.pos as u64).saturating_add_signed(off),
        };
        self.pos = pos.try_into().map_err(|_| io::ErrorKind::UnexpectedEof)?;
        Ok(pos)
    }
}
