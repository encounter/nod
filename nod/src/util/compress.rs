use std::io;

use tracing::instrument;

use crate::{
    Error, Result,
    common::Compression,
    io::wia::{WIACompression, WIADisc},
};

#[derive(Debug, Clone)]
pub enum DecompressionKind {
    None,
    #[cfg(feature = "compress-zlib")]
    Deflate,
    #[cfg(feature = "compress-bzip2")]
    Bzip2,
    #[cfg(feature = "compress-lzma")]
    Lzma(Box<[u8]>),
    #[cfg(feature = "compress-lzma")]
    Lzma2(Box<[u8]>),
    #[cfg(feature = "compress-zstd")]
    Zstandard,
}

impl DecompressionKind {
    pub fn from_wia(disc: &WIADisc) -> Result<Self> {
        let _data = &disc.compr_data[..disc.compr_data_len as usize];
        match disc.compression() {
            WIACompression::None => Ok(Self::None),
            #[cfg(feature = "compress-bzip2")]
            WIACompression::Bzip2 => Ok(Self::Bzip2),
            #[cfg(feature = "compress-lzma")]
            WIACompression::Lzma => Ok(Self::Lzma(Box::from(_data))),
            #[cfg(feature = "compress-lzma")]
            WIACompression::Lzma2 => Ok(Self::Lzma2(Box::from(_data))),
            #[cfg(feature = "compress-zstd")]
            WIACompression::Zstandard => Ok(Self::Zstandard),
            comp => Err(Error::DiscFormat(format!("Unsupported WIA/RVZ compression: {:?}", comp))),
        }
    }

    #[instrument(name = "DecompressionKind::decompress", skip_all)]
    pub fn decompress(&self, buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        match self {
            DecompressionKind::None => {
                if buf.len() > out.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Decompressed data too large: {} > {}", buf.len(), out.len()),
                    ));
                }
                out[..buf.len()].copy_from_slice(buf);
                Ok(buf.len())
            }
            #[cfg(feature = "compress-zlib")]
            DecompressionKind::Deflate => zlib_api::decompress(buf, out),
            #[cfg(feature = "compress-bzip2")]
            DecompressionKind::Bzip2 => bzip2_api::decompress(buf, out),
            #[cfg(feature = "compress-lzma")]
            DecompressionKind::Lzma(data) => lzma_api::decompress_lzma(data, buf, out),
            #[cfg(feature = "compress-lzma")]
            DecompressionKind::Lzma2(data) => lzma_api::decompress_lzma2(data, buf, out),
            #[cfg(feature = "compress-zstd")]
            DecompressionKind::Zstandard => zstd_api::decompress(buf, out),
        }
    }

    pub fn get_content_size(&self, buf: &[u8]) -> io::Result<Option<usize>> {
        match self {
            DecompressionKind::None => Ok(Some(buf.len())),
            #[cfg(feature = "compress-zstd")]
            DecompressionKind::Zstandard => zstd_api::get_content_size(buf),
            #[allow(unreachable_patterns)] // if compression features are disabled
            _ => Ok(None),
        }
    }
}

pub struct Compressor {
    pub kind: Compression,
    pub buffer: Vec<u8>,
}

impl Clone for Compressor {
    fn clone(&self) -> Self {
        Self { kind: self.kind, buffer: Vec::with_capacity(self.buffer.capacity()) }
    }
}

impl Compressor {
    pub fn new(kind: Compression, buffer_size: usize) -> Self {
        Self { kind, buffer: Vec::with_capacity(buffer_size) }
    }

    /// Compresses the given buffer into `out`. `out`'s capacity will not be extended. Instead, if
    /// the compressed data is larger than `out`, this function will bail and return `false`.
    #[instrument(name = "Compressor::compress", skip_all)]
    pub fn compress(&mut self, buf: &[u8]) -> io::Result<bool> {
        self.buffer.clear();
        match self.kind {
            Compression::None => {
                if self.buffer.capacity() >= buf.len() {
                    self.buffer.extend_from_slice(buf);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            #[cfg(feature = "compress-zlib")]
            Compression::Deflate(level) => zlib_api::compress(buf, level, &mut self.buffer),
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2(level) => bzip2_api::compress(buf, level, &mut self.buffer),
            #[cfg(feature = "compress-lzma")]
            Compression::Lzma(level) => lzma_api::compress_lzma(level, buf, &mut self.buffer),
            #[cfg(feature = "compress-lzma")]
            Compression::Lzma2(level) => lzma_api::compress_lzma2(level, buf, &mut self.buffer),
            #[cfg(feature = "compress-zstd")]
            Compression::Zstandard(level) => zstd_api::compress(buf, level, &mut self.buffer),
            #[allow(unreachable_patterns)] // if compression is disabled
            _ => Err(io::Error::other(format!("Unsupported compression: {:?}", self.kind))),
        }
    }
}

// Decode through EOF even when the destination is exactly full, so trailers,
// checksums and truncated streams are checked rather than silently accepted.
#[cfg(any(
    feature = "compress-zlib",
    feature = "compress-bzip2",
    feature = "compress-lzma",
    feature = "compress-zstd"
))]
fn decompress_into(mut reader: impl io::Read, out: &mut [u8]) -> io::Result<usize> {
    let mut len = 0;
    while len < out.len() {
        match reader.read(&mut out[len..]) {
            Ok(0) => return Ok(len),
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let mut extra = [0];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => return Ok(len),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Decompression output buffer too small",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

// A slice-backed writer cannot grow the caller's output buffer. WriteZero means
// the compressed block did not fit and the disc writer should store it verbatim.
#[cfg(any(feature = "compress-zlib", feature = "compress-lzma", feature = "compress-zstd"))]
fn compress_into(
    out: &mut Vec<u8>,
    encode: impl FnOnce(&mut io::Cursor<&mut [u8]>) -> io::Result<()>,
) -> io::Result<bool> {
    out.resize(out.capacity(), 0);
    let mut writer = io::Cursor::new(out.as_mut_slice());
    let result = encode(&mut writer);
    let len = writer.position() as usize;
    match result {
        Ok(()) => {
            out.truncate(len);
            Ok(true)
        }
        Err(e) => {
            out.clear();
            if e.kind() == io::ErrorKind::WriteZero { Ok(false) } else { Err(e) }
        }
    }
}

#[cfg(feature = "compress-zlib")]
mod zlib_api {
    use std::io::{self, Write};

    pub fn decompress(buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        super::decompress_into(flate2::bufread::ZlibDecoder::new(buf), out)
    }

    pub fn compress(buf: &[u8], level: u8, out: &mut Vec<u8>) -> io::Result<bool> {
        if level > 9 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid zlib level"));
        }
        super::compress_into(out, |writer| {
            let mut encoder =
                flate2::write::ZlibEncoder::new(writer, flate2::Compression::new(level.into()));
            encoder.write_all(buf)?;
            encoder.finish()?;
            Ok(())
        })
    }
}

#[cfg(feature = "compress-bzip2")]
mod bzip2_api {
    use std::io;

    pub fn decompress(buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        super::decompress_into(bzip2::bufread::BzDecoder::new(buf), out)
    }

    pub fn compress(buf: &[u8], level: u8, out: &mut Vec<u8>) -> io::Result<bool> {
        if !(1..=9).contains(&level) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid bzip2 level"));
        }
        if out.capacity() == 0 {
            return Ok(false);
        }
        out.resize(out.capacity(), 0);
        let mut encoder = bzip2::Compress::new(bzip2::Compression::new(level.into()), 30);
        loop {
            let before = (encoder.total_in(), encoder.total_out());
            let status = encoder
                .compress(
                    &buf[before.0 as usize..],
                    &mut out[before.1 as usize..],
                    bzip2::Action::Finish,
                )
                .map_err(io::Error::other)?;
            if status == bzip2::Status::StreamEnd {
                out.truncate(encoder.total_out() as usize);
                return Ok(true);
            }
            if encoder.total_out() as usize == out.len() {
                out.clear();
                return Ok(false);
            }
            if before == (encoder.total_in(), encoder.total_out()) {
                return Err(io::Error::other("bzip2 compressor made no progress"));
            }
        }
    }
}

#[cfg(feature = "compress-zstd")]
pub(crate) mod zstd_api {
    use std::io::{self, Write};

    use structured_zstd::{
        decoding::{ContentChecksum, FrameContentSize, StreamingDecoder, read_frame_content_size},
        encoding::{CompressionLevel, StreamingEncoder},
    };

    pub fn compress_bound(size: usize) -> usize {
        // A frame header, checksum and a three-byte header for each raw block.
        size.saturating_add(size.div_ceil(128 * 1024).max(1).saturating_mul(3))
            .saturating_add(18 + 4)
    }

    pub fn decompress(buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let mut decoder = StreamingDecoder::new(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        decoder.decoder_mut().set_content_checksum(ContentChecksum::Verify);
        super::decompress_into(decoder, out)
    }

    pub fn compress(buf: &[u8], level: i8, out: &mut Vec<u8>) -> io::Result<bool> {
        super::compress_into(out, |writer| {
            let mut encoder =
                StreamingEncoder::new(writer, CompressionLevel::from_level(level.into()));
            encoder.set_pledged_content_size(buf.len() as u64)?;
            encoder.write_all(buf)?;
            encoder.finish()?;
            Ok(())
        })
    }

    pub fn get_content_size(buf: &[u8]) -> io::Result<Option<usize>> {
        match read_frame_content_size(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            FrameContentSize::Unknown => Ok(None),
            FrameContentSize::Known(size) => usize::try_from(size).map(Some).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Zstandard frame size exceeds usize")
            }),
        }
    }
}

#[cfg(feature = "compress-lzma")]
pub(crate) mod lzma_api {
    use std::io::{self, Write};

    use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer, LzmaOptions, LzmaReader, LzmaWriter};

    fn preset_options(level: u32) -> io::Result<LzmaOptions> {
        if level > 9 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid LZMA preset"));
        }
        Ok(LzmaOptions::with_preset(level))
    }

    pub fn compress_lzma(level: u8, buf: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        let options = preset_options(level.into())?;
        super::compress_into(out, |writer| {
            // WIA stores the properties separately and uses an end marker.
            let mut encoder = LzmaWriter::new_no_header(writer, &options, true)?;
            encoder.write_all(buf)?;
            encoder.finish()?;
            Ok(())
        })
    }

    pub fn compress_lzma2(level: u8, buf: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        let options =
            Lzma2Options { lzma_options: preset_options(level.into())?, chunk_size: None };
        super::compress_into(out, |writer| {
            let mut encoder = Lzma2Writer::new(writer, options);
            encoder.write_all(buf)?;
            encoder.finish()?;
            Ok(())
        })
    }

    pub fn decompress_lzma(props: &[u8], buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let [prop, a, b, c, d] = *props else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid LZMA properties length",
            ));
        };
        let dict_size = u32::from_le_bytes([a, b, c, d]);
        let mut input = buf;
        let decoder = LzmaReader::new_with_props(&mut input, u64::MAX, prop, dict_size, None)?;
        let len = super::decompress_into(decoder, out)?;
        if !input.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Trailing LZMA data"));
        }
        Ok(len)
    }

    pub fn decompress_lzma2(props: &[u8], buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let [prop @ 0..=40] = *props else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid LZMA2 properties"));
        };
        let dict_size =
            if prop == 40 { u32::MAX } else { (2 | (u32::from(prop) & 1)) << (prop / 2 + 11) };
        // No back-reference can reach further than the maximum output size.
        let dict_size = dict_size.min(u32::try_from(out.len()).unwrap_or(u32::MAX)).max(4096);
        let mut input = buf;
        let decoder = Lzma2Reader::new(&mut input, dict_size, None);
        let len = super::decompress_into(decoder, out)?;
        if !input.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Trailing LZMA2 data"));
        }
        Ok(len)
    }

    pub fn lzma_props_encode_preset(level: u32) -> io::Result<[u8; 5]> {
        let options = preset_options(level)?;
        let mut props = [0; 5];
        props[0] = options.get_props();
        props[1..].copy_from_slice(&options.dict_size.to_le_bytes());
        Ok(props)
    }

    pub fn lzma2_props_encode_preset(level: u32) -> io::Result<[u8; 1]> {
        let dict_size = preset_options(level)?.dict_size;
        let prop = (0u8..40)
            .find(|&p| dict_size <= (2 | (u32::from(p) & 1)) << (p / 2 + 11))
            .unwrap_or(40);
        Ok([prop])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_data() -> Vec<u8> {
        let mut data = b"nod pure Rust compression fixture\n".repeat(1024);
        data.extend((0..256).flat_map(|_| 0u8..=255));
        data
    }

    fn codecs() -> Vec<(Compression, DecompressionKind, &'static [u8])> {
        vec![
            #[cfg(feature = "compress-zlib")]
            (
                Compression::Deflate(6),
                DecompressionKind::Deflate,
                include_bytes!("../../tests/fixtures/compression/reference.zlib"),
            ),
            #[cfg(feature = "compress-bzip2")]
            (
                Compression::Bzip2(6),
                DecompressionKind::Bzip2,
                include_bytes!("../../tests/fixtures/compression/reference.bz2"),
            ),
            #[cfg(feature = "compress-lzma")]
            (
                Compression::Lzma(6),
                DecompressionKind::Lzma(Box::from([0x5d, 0, 0, 0x80, 0])),
                include_bytes!("../../tests/fixtures/compression/reference.lzma"),
            ),
            #[cfg(feature = "compress-lzma")]
            (
                Compression::Lzma2(6),
                DecompressionKind::Lzma2(Box::from([22])),
                include_bytes!("../../tests/fixtures/compression/reference.lzma2"),
            ),
            #[cfg(feature = "compress-zstd")]
            (
                Compression::Zstandard(6),
                DecompressionKind::Zstandard,
                include_bytes!("../../tests/fixtures/compression/reference.zst"),
            ),
        ]
    }

    #[test]
    fn native_codec_compatibility() {
        let expected = reference_data();
        for (kind, decoder, compressed) in codecs() {
            for size in [expected.len(), expected.len() + 16] {
                let mut out = vec![0; size];
                let len = decoder
                    .decompress(compressed, &mut out)
                    .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
                assert_eq!(&out[..len], expected, "{kind:?}");
            }
            assert!(
                decoder.decompress(compressed, &mut vec![0; expected.len() - 1]).is_err(),
                "{kind:?}: undersized output"
            );
            assert!(
                decoder
                    .decompress(&compressed[..compressed.len() - 1], &mut vec![0; expected.len()])
                    .is_err(),
                "{kind:?}: truncated input"
            );
            assert!(
                decoder.decompress(b"invalid compressed data", &mut [0; 32]).is_err(),
                "{kind:?}: invalid input"
            );
        }
    }

    #[test]
    fn bounded_roundtrips() {
        // Include multiple Zstd/LZMA2 blocks, empty input and incompressible data.
        let mut random = vec![0; 32768];
        let mut state = 0x12345678u32;
        for byte in &mut random {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        for (kind, decoder, _) in codecs() {
            for data in [Vec::new(), vec![42], random.clone(), reference_data().repeat(4)] {
                let mut compressor = Compressor::new(kind, data.len() * 2 + 1024);
                let capacity = compressor.buffer.capacity();
                assert!(
                    compressor
                        .compress(&data)
                        .unwrap_or_else(|e| panic!("{kind:?}, input {}: {e}", data.len())),
                    "{kind:?}"
                );
                assert_eq!(compressor.buffer.capacity(), capacity);
                let mut out = vec![0; data.len()];
                let len = decoder
                    .decompress(&compressor.buffer, &mut out)
                    .unwrap_or_else(|e| panic!("{kind:?}, {} bytes: {e}", data.len()));
                assert_eq!(len, data.len(), "{kind:?}");
                assert_eq!(out, data, "{kind:?}");
                for capacity in [0, 1, compressor.buffer.len() - 1]
                    .into_iter()
                    .filter(|&n| n < compressor.buffer.len())
                {
                    let mut tiny = Compressor::new(kind, capacity);
                    assert!(
                        !tiny.compress(&data).unwrap_or_else(|e| panic!(
                            "{kind:?}, input {} capacity {capacity}: {e}",
                            data.len()
                        )),
                        "{kind:?}: capacity {capacity}"
                    );
                    assert!(tiny.buffer.is_empty());
                    assert_eq!(tiny.buffer.capacity(), capacity);
                }
            }
        }
    }

    #[cfg(feature = "compress-zstd")]
    #[test]
    fn zstd_sizes_and_checksums() {
        let expected = reference_data();
        let known = include_bytes!("../../tests/fixtures/compression/reference.zst");
        let unknown = include_bytes!("../../tests/fixtures/compression/unknown-size.zst");
        assert_eq!(zstd_api::get_content_size(known).unwrap(), Some(expected.len()));
        assert_eq!(zstd_api::get_content_size(unknown).unwrap(), None);
        assert!(zstd_api::get_content_size(&known[..5]).is_err());
        let mut out = vec![0; expected.len()];
        assert_eq!(zstd_api::decompress(unknown, &mut out).unwrap(), expected.len());
        assert_eq!(out, expected);
        let mut corrupted = known.to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(zstd_api::decompress(&corrupted, &mut out).is_err());
        let mut empty = Compressor::new(Compression::Zstandard(3), 64);
        assert!(empty.compress(&[]).unwrap());
        assert_eq!(zstd_api::get_content_size(&empty.buffer).unwrap(), Some(0));
    }

    #[cfg(feature = "compress-lzma")]
    #[test]
    fn lzma_properties() {
        assert_eq!(lzma_api::lzma_props_encode_preset(6).unwrap(), [0x5d, 0, 0, 0x80, 0]);
        assert_eq!(lzma_api::lzma2_props_encode_preset(6).unwrap(), [22]);
        assert!(lzma_api::lzma_props_encode_preset(10).is_err());
        for props in [&[][..], &[0xff][..], &[0xff; 5][..]] {
            assert!(lzma_api::decompress_lzma(props, &[], &mut []).is_err());
            assert!(lzma_api::decompress_lzma2(props, &[], &mut []).is_err());
        }
    }
}
