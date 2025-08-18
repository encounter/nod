pub mod digest;
pub mod redump;
pub mod shared;

use std::{
    fmt,
    fmt::Write,
    path::{MAIN_SEPARATOR, Path},
};

pub fn path_display(path: &Path) -> PathDisplay<'_> { PathDisplay { path } }

pub struct PathDisplay<'a> {
    path: &'a Path,
}

impl fmt::Display for PathDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for segment in self.path.iter() {
            let segment_str = segment.to_string_lossy();
            if segment_str == "/" || segment_str == "." {
                continue;
            }
            if first {
                first = false;
            } else {
                f.write_char(MAIN_SEPARATOR)?;
            }
            f.write_str(&segment_str)?;
        }
        Ok(())
    }
}

pub fn has_extension(filename: &Path, extension: &str) -> bool {
    match filename.extension() {
        Some(ext) => ext.eq_ignore_ascii_case(extension),
        None => false,
    }
}

/// Creates a fixed-size array reference from a slice.
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline(always)]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }};
}
pub(crate) use array_ref;
