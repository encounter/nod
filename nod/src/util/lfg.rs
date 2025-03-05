//! Lagged Fibonacci generator for GC / Wii partition junk data.

use std::{
    io,
    io::{Read, Write},
};

use bytes::Buf;
use tracing::instrument;
use zerocopy::{IntoBytes, transmute_ref};

use crate::{disc::SECTOR_SIZE, util::array_ref_mut};

/// Value of `k` for the LFG.
pub const LFG_K: usize = 521;

/// Value of `k` for the LFG in bytes.
pub const LFG_K_BYTES: usize = LFG_K * 4;

/// Value of `j` for the LFG.
pub const LFG_J: usize = 32;

/// Number of 32-bit words in the seed.
pub const SEED_SIZE: usize = 17;

/// Size of the seed in bytes.
pub const SEED_SIZE_BYTES: usize = SEED_SIZE * 4;

/// Lagged Fibonacci generator for GC / Wii partition junk data.
///
/// References (license CC0-1.0):
/// - [WiaAndRvz.md](https://github.com/dolphin-emu/dolphin/blob/a0f555648c27ec0c928f6b1e1fcad5e2d7c4d0c4/docs/WiaAndRvz.md)
/// - [LaggedFibonacciGenerator.cpp](https://github.com/dolphin-emu/dolphin/blob/a0f555648c27ec0c928f6b1e1fcad5e2d7c4d0c4/Source/Core/DiscIO/LaggedFibonacciGenerator.cpp)
pub struct LaggedFibonacci {
    buffer: [u32; LFG_K],
    position: usize,
}

impl Default for LaggedFibonacci {
    #[inline]
    fn default() -> Self { Self { buffer: [0u32; LFG_K], position: 0 } }
}

impl LaggedFibonacci {
    fn init(&mut self) {
        for i in SEED_SIZE..LFG_K {
            self.buffer[i] = (self.buffer[i - SEED_SIZE] << 23)
                ^ (self.buffer[i - SEED_SIZE + 1] >> 9)
                ^ self.buffer[i - 1];
        }
        // Instead of doing the "shift by 18 instead of 16" oddity when actually outputting the data,
        // we can do the shifting (and byteswapping) at this point to make the output code simpler.
        for x in self.buffer.iter_mut() {
            *x = ((*x & 0xFF00FFFF) | (*x >> 2 & 0x00FF0000)).to_be();
        }
        for _ in 0..4 {
            self.forward();
        }
    }

    /// Generates the seed for GC / Wii partition junk data using the disc ID, disc number, and sector.
    pub fn generate_seed(out: &mut [u32; SEED_SIZE], disc_id: [u8; 4], disc_num: u8, sector: u32) {
        let seed = u32::from_be_bytes([
            disc_id[2],
            disc_id[1],
            disc_id[3].wrapping_add(disc_id[2]),
            disc_id[0].wrapping_add(disc_id[1]),
        ]) ^ disc_num as u32;
        let mut n = seed.wrapping_mul(0x260BCD5) ^ sector.wrapping_mul(0x1EF29123);
        for v in &mut *out {
            *v = 0u32;
            for _ in 0..LFG_J {
                n = n.wrapping_mul(0x5D588B65).wrapping_add(1);
                *v = (*v >> 1) | (n & 0x80000000);
            }
        }
        out[16] ^= out[0] >> 9 ^ out[16] << 23;
    }

    /// Same as [`generate_seed`], but ensures the resulting seed is big-endian.
    pub fn generate_seed_be(
        out: &mut [u32; SEED_SIZE],
        disc_id: [u8; 4],
        disc_num: u8,
        sector: u32,
    ) {
        Self::generate_seed(out, disc_id, disc_num, sector);
        for x in out.iter_mut() {
            *x = x.to_be();
        }
    }

    /// Initializes the LFG with the standard seed for a given disc ID, disc number, and sector.
    /// The partition offset is used to determine the sector and how many bytes to skip within the
    /// sector.
    #[instrument(name = "LaggedFibonacci::init_with_seed", skip_all)]
    pub fn init_with_seed(&mut self, disc_id: [u8; 4], disc_num: u8, partition_offset: u64) {
        let sector = (partition_offset / SECTOR_SIZE as u64) as u32;
        let sector_offset = (partition_offset % SECTOR_SIZE as u64) as usize;
        Self::generate_seed(array_ref_mut![self.buffer, 0, SEED_SIZE], disc_id, disc_num, sector);
        self.position = 0;
        self.init();
        self.skip(sector_offset);
    }

    /// Initializes the LFG with the seed read from a reader. The seed is assumed to be big-endian.
    /// This is used for rebuilding junk data in WIA/RVZ files.
    #[instrument(name = "LaggedFibonacci::init_with_reader", skip_all)]
    pub fn init_with_reader<R>(&mut self, reader: &mut R) -> io::Result<()>
    where R: Read + ?Sized {
        reader.read_exact(self.buffer[..SEED_SIZE].as_mut_bytes())?;
        for x in self.buffer[..SEED_SIZE].iter_mut() {
            *x = u32::from_be(*x);
        }
        self.position = 0;
        self.init();
        Ok(())
    }

    /// Initializes the LFG with the seed read from a [`Buf`]. The seed is assumed to be big-endian.
    /// This is used for rebuilding junk data in WIA/RVZ files.
    #[instrument(name = "LaggedFibonacci::init_with_buf", skip_all)]
    pub fn init_with_buf(&mut self, reader: &mut impl Buf) -> io::Result<()> {
        let out = self.buffer[..SEED_SIZE].as_mut_bytes();
        if reader.remaining() < out.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Filling LFG seed"));
        }
        reader.copy_to_slice(out);
        for x in self.buffer[..SEED_SIZE].iter_mut() {
            *x = u32::from_be(*x);
        }
        self.position = 0;
        self.init();
        Ok(())
    }

    /// Advances the LFG by one step.
    // This gets vectorized and aggressively inlined, so it's better to
    // keep it separate for code size and instruction cache pressure.
    #[inline(never)]
    fn forward(&mut self) {
        for i in 0..LFG_J {
            self.buffer[i] ^= self.buffer[i + LFG_K - LFG_J];
        }
        for i in LFG_J..LFG_K {
            self.buffer[i] ^= self.buffer[i - LFG_J];
        }
    }

    /// Skips `n` bytes of junk data.
    pub fn skip(&mut self, n: usize) {
        self.position += n;
        while self.position >= LFG_K_BYTES {
            self.forward();
            self.position -= LFG_K_BYTES;
        }
    }

    /// Fills the buffer with junk data.
    #[instrument(name = "LaggedFibonacci::fill", skip_all)]
    pub fn fill(&mut self, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            while self.position >= LFG_K_BYTES {
                self.forward();
                self.position -= LFG_K_BYTES;
            }
            let bytes: &[u8; LFG_K_BYTES] = transmute_ref!(&self.buffer);
            let len = buf.len().min(LFG_K_BYTES - self.position);
            buf[..len].copy_from_slice(&bytes[self.position..self.position + len]);
            self.position += len;
            buf = &mut buf[len..];
        }
    }

    /// Writes junk data to the output stream.
    #[instrument(name = "LaggedFibonacci::write", skip_all)]
    pub fn write<W>(&mut self, w: &mut W, mut len: u64) -> io::Result<()>
    where W: Write + ?Sized {
        while len > 0 {
            while self.position >= LFG_K_BYTES {
                self.forward();
                self.position -= LFG_K_BYTES;
            }
            let bytes: &[u8; LFG_K_BYTES] = transmute_ref!(&self.buffer);
            let write_len = len.min((LFG_K_BYTES - self.position) as u64) as usize;
            w.write_all(&bytes[self.position..self.position + write_len])?;
            self.position += write_len;
            len -= write_len as u64;
        }
        Ok(())
    }

    /// The junk data on GC / Wii discs is reinitialized every 32KB. This functions handles the
    /// wrapping logic and reinitializes the LFG at sector boundaries.
    #[instrument(name = "LaggedFibonacci::fill_sector_chunked", skip_all)]
    pub fn fill_sector_chunked(
        &mut self,
        mut buf: &mut [u8],
        disc_id: [u8; 4],
        disc_num: u8,
        mut partition_offset: u64,
    ) {
        while !buf.is_empty() {
            self.init_with_seed(disc_id, disc_num, partition_offset);
            let len =
                (SECTOR_SIZE - (partition_offset % SECTOR_SIZE as u64) as usize).min(buf.len());
            self.fill(&mut buf[..len]);
            buf = &mut buf[len..];
            partition_offset += len as u64;
        }
    }

    /// The junk data on GC / Wii discs is reinitialized every 32KB. This functions handles the
    /// wrapping logic and reinitializes the LFG at sector boundaries.
    #[instrument(name = "LaggedFibonacci::write_sector_chunked", skip_all)]
    pub fn write_sector_chunked<W>(
        &mut self,
        w: &mut W,
        mut len: u64,
        disc_id: [u8; 4],
        disc_num: u8,
        mut partition_offset: u64,
    ) -> io::Result<()>
    where
        W: Write + ?Sized,
    {
        while len > 0 {
            self.init_with_seed(disc_id, disc_num, partition_offset);
            let write_len = (SECTOR_SIZE as u64 - (partition_offset % SECTOR_SIZE as u64)).min(len);
            self.write(w, write_len)?;
            len -= write_len;
            partition_offset += write_len;
        }
        Ok(())
    }

    /// Checks if the data matches the junk data generated by the LFG, up to the first sector
    /// boundary.
    #[instrument(name = "LaggedFibonacci::check", skip_all)]
    pub fn check(
        &mut self,
        buf: &[u8],
        disc_id: [u8; 4],
        disc_num: u8,
        partition_offset: u64,
    ) -> usize {
        let mut lfg_buf = [0u8; SECTOR_SIZE];
        self.init_with_seed(disc_id, disc_num, partition_offset);
        let len = (SECTOR_SIZE - (partition_offset % SECTOR_SIZE as u64) as usize).min(buf.len());
        self.fill(&mut lfg_buf[..len]);
        buf[..len].iter().zip(&lfg_buf[..len]).take_while(|(a, b)| a == b).count()
    }

    /// Checks if the data matches the junk data generated by the LFG. This function handles the
    /// wrapping logic and reinitializes the LFG at sector boundaries.
    #[instrument(name = "LaggedFibonacci::check_sector_chunked", skip_all)]
    pub fn check_sector_chunked(
        &mut self,
        mut buf: &[u8],
        disc_id: [u8; 4],
        disc_num: u8,
        mut partition_offset: u64,
    ) -> usize {
        let mut lfg_buf = [0u8; SECTOR_SIZE];
        let mut total_num_matching = 0;
        while !buf.is_empty() {
            self.init_with_seed(disc_id, disc_num, partition_offset);
            let len =
                (SECTOR_SIZE - (partition_offset % SECTOR_SIZE as u64) as usize).min(buf.len());
            self.fill(&mut lfg_buf[..len]);
            let num_matching =
                buf[..len].iter().zip(&lfg_buf[..len]).take_while(|(a, b)| a == b).count();
            total_num_matching += num_matching;
            if num_matching != len {
                break;
            }
            buf = &buf[len..];
            partition_offset += len as u64;
        }
        total_num_matching
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_with_seed_1() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x41, 0x4c, 0x45], 0, 0x600000);
        let mut buf = [0u8; 16];
        lfg.fill(&mut buf);
        assert_eq!(buf, [
            0xE9, 0x47, 0x67, 0xBD, 0x41, 0x50, 0x4D, 0x5D, 0x61, 0x48, 0xB1, 0x99, 0xA0, 0x12,
            0x0C, 0xBA
        ]);
    }

    #[test]
    fn test_init_with_seed_2() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x41, 0x4c, 0x45], 0, 0x608000);
        let mut buf = [0u8; 16];
        lfg.fill(&mut buf);
        assert_eq!(buf, [
            0xE2, 0xBB, 0xBD, 0x77, 0xDA, 0xB2, 0x22, 0x42, 0x1C, 0x0C, 0x0B, 0xFC, 0xAC, 0x06,
            0xEA, 0xD0
        ]);
    }

    #[test]
    fn test_init_with_seed_3() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x50, 0x49, 0x45], 0, 0x322904);
        let mut buf = [0u8; 16];
        lfg.fill(&mut buf);
        assert_eq!(buf, [
            0x97, 0xD8, 0x23, 0x0B, 0x12, 0xAA, 0x20, 0x45, 0xC2, 0xBD, 0x71, 0x8C, 0x30, 0x32,
            0xC5, 0x2F
        ]);
    }

    #[test]
    fn test_write() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x50, 0x49, 0x45], 0, 0x322904);
        let mut buf = [0u8; 16];
        lfg.write(&mut buf.as_mut_slice(), 16).unwrap();
        assert_eq!(buf, [
            0x97, 0xD8, 0x23, 0x0B, 0x12, 0xAA, 0x20, 0x45, 0xC2, 0xBD, 0x71, 0x8C, 0x30, 0x32,
            0xC5, 0x2F
        ]);
    }

    #[test]
    fn test_fill_sector_chunked() {
        let mut lfg = LaggedFibonacci::default();
        let mut buf = [0u8; 32];
        lfg.fill_sector_chunked(&mut buf, [0x47, 0x4D, 0x38, 0x45], 0, 0x27FF0);
        assert_eq!(buf, [
            0xAD, 0x6F, 0x21, 0xBE, 0x05, 0x57, 0x10, 0xED, 0xEA, 0xB0, 0x8E, 0xFD, 0x91, 0x58,
            0xA2, 0x0E, 0xDC, 0x0D, 0x59, 0xC0, 0x02, 0x98, 0xA5, 0x00, 0x39, 0x5B, 0x68, 0xA6,
            0x5D, 0x53, 0x2D, 0xB6
        ]);
    }

    #[test]
    fn test_write_sector_chunked() {
        let mut lfg = LaggedFibonacci::default();
        let mut buf = [0u8; 32];
        lfg.write_sector_chunked(&mut buf.as_mut_slice(), 32, [0x47, 0x4D, 0x38, 0x45], 0, 0x27FF0)
            .unwrap();
        assert_eq!(buf, [
            0xAD, 0x6F, 0x21, 0xBE, 0x05, 0x57, 0x10, 0xED, 0xEA, 0xB0, 0x8E, 0xFD, 0x91, 0x58,
            0xA2, 0x0E, 0xDC, 0x0D, 0x59, 0xC0, 0x02, 0x98, 0xA5, 0x00, 0x39, 0x5B, 0x68, 0xA6,
            0x5D, 0x53, 0x2D, 0xB6
        ]);
    }
}
