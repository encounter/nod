use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use crate::{ErrorContext, Result, ResultContext, read::DiscStream};

#[derive(Debug)]
pub struct SplitFileReader {
    files: Vec<Split<PathBuf>>,
    open_file: Option<Split<File>>,
}

#[derive(Debug, Clone)]
struct Split<T> {
    inner: T,
    begin: u64,
    size: u64,
}

impl<T> Split<T> {
    fn contains(&self, pos: u64) -> bool { self.begin <= pos && pos < self.begin + self.size }
}

// .iso.1, .iso.2, etc.
fn split_path_1(input: &Path, index: u32) -> PathBuf {
    let input_str = input.to_str().unwrap_or("[INVALID]");
    let mut out = input_str.to_string();
    out.push('.');
    out.push(char::from_digit(index, 10).unwrap());
    PathBuf::from(out)
}

// .part1.iso, .part2.iso, etc.
fn split_path_2(input: &Path, index: u32) -> PathBuf {
    let extension = input.extension().and_then(|s| s.to_str()).unwrap_or("iso");
    let input_without_ext = input.with_extension("");
    let input_str = input_without_ext.to_str().unwrap_or("[INVALID]");
    let mut out = input_str.to_string();
    out.push_str(".part");
    out.push(char::from_digit(index, 10).unwrap());
    out.push('.');
    out.push_str(extension);
    PathBuf::from(out)
}

// .wbf1, .wbf2, etc.
fn split_path_3(input: &Path, index: u32) -> PathBuf {
    let input_str = input.to_str().unwrap_or("[INVALID]");
    let mut chars = input_str.chars();
    chars.next_back();
    let mut out = chars.as_str().to_string();
    out.push(char::from_digit(index, 10).unwrap());
    PathBuf::from(out)
}

impl SplitFileReader {
    pub fn empty() -> Self { Self { files: Vec::new(), open_file: Default::default() } }

    pub fn new(path: &Path) -> Result<Self> {
        let mut files = vec![];
        let mut begin = 0;
        match path.metadata() {
            Ok(metadata) => {
                files.push(Split { inner: path.to_path_buf(), begin, size: metadata.len() });
                begin += metadata.len();
            }
            Err(e) => {
                return Err(e.context(format!("Failed to stat file {}", path.display())));
            }
        }
        for path_fn in [split_path_1, split_path_2, split_path_3] {
            let mut index = 1;
            loop {
                let path = path_fn(path, index);
                if let Ok(metadata) = path.metadata() {
                    files.push(Split { inner: path, begin, size: metadata.len() });
                    begin += metadata.len();
                    index += 1;
                } else {
                    break;
                }
            }
            if index > 1 {
                break;
            }
        }
        Ok(Self { files, open_file: Default::default() })
    }

    pub fn add(&mut self, path: &Path) -> Result<()> {
        let begin = self.len();
        let metadata =
            path.metadata().context(format!("Failed to stat file {}", path.display()))?;
        self.files.push(Split { inner: path.to_path_buf(), begin, size: metadata.len() });
        Ok(())
    }

    pub fn len(&self) -> u64 { self.files.last().map_or(0, |f| f.begin + f.size) }
}

impl Clone for SplitFileReader {
    fn clone(&self) -> Self { Self { files: self.files.clone(), open_file: Default::default() } }
}

impl DiscStream for SplitFileReader {
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let split = if self.open_file.as_ref().is_none_or(|s| !s.contains(offset)) {
            let split = if let Some(split) = self.files.iter().find(|f| f.contains(offset)) {
                let file = File::open(&split.inner)?;
                Split { inner: file, begin: split.begin, size: split.size }
            } else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            self.open_file.insert(split)
        } else {
            self.open_file.as_mut().unwrap()
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            split.inner.read_exact_at(buf, offset)
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            split.inner.seek(SeekFrom::Start(offset - split.begin))?;
            split.inner.read_exact(buf)
        }
    }

    fn stream_len(&mut self) -> io::Result<u64> { Ok(self.len()) }
}
