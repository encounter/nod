use std::{io, io::Read, sync::Arc};

use zerocopy::{FromBytes, FromZeros, IntoBytes};

#[inline(always)]
pub fn read_from<T, R>(reader: &mut R) -> io::Result<T>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_zeroed();
    reader.read_exact(ret.as_mut_bytes())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_vec<T, R>(reader: &mut R, count: usize) -> io::Result<Vec<T>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret =
        <T>::new_vec_zeroed(count).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    reader.read_exact(ret.as_mut_slice().as_mut_bytes())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_box<T, R>(reader: &mut R) -> io::Result<Box<T>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_box_zeroed().map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    reader.read_exact(ret.as_mut().as_mut_bytes())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_arc<T, R>(reader: &mut R) -> io::Result<Arc<T>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    // TODO use Arc::new_zeroed once it's stable
    read_box(reader).map(Arc::from)
}

#[inline(always)]
pub fn read_box_slice<T, R>(reader: &mut R, count: usize) -> io::Result<Box<[T]>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret = <[T]>::new_box_zeroed_with_elems(count)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    reader.read_exact(ret.as_mut().as_mut_bytes())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_arc_slice<T, R>(reader: &mut R, count: usize) -> io::Result<Arc<[T]>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    // TODO use Arc::new_zeroed once it's stable
    read_box_slice(reader, count).map(Arc::from)
}

#[inline(always)]
pub fn read_u16_be<R>(reader: &mut R) -> io::Result<u16>
where R: Read + ?Sized {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

#[inline(always)]
pub fn read_u32_be<R>(reader: &mut R) -> io::Result<u32>
where R: Read + ?Sized {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

#[inline(always)]
pub fn read_u64_be<R>(reader: &mut R) -> io::Result<u64>
where R: Read + ?Sized {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

pub fn read_with_zero_fill<R>(r: &mut R, mut buf: &mut [u8]) -> io::Result<usize>
where R: Read + ?Sized {
    let mut total = 0;
    while !buf.is_empty() {
        let read = r.read(buf)?;
        if read == 0 {
            // Fill remaining block with zeroes
            buf.fill(0);
            break;
        }
        buf = &mut buf[read..];
        total += read;
    }
    Ok(total)
}

pub fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]>
where T: IntoBytes {
    let p = Box::into_raw(b);
    let sp = unsafe { std::slice::from_raw_parts_mut(p as *mut u8, size_of::<T>()) };
    unsafe { Box::from_raw(sp) }
}
