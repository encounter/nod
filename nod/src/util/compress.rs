use std::io;

use tracing::instrument;

use crate::{
    Error, Result,
    common::Compression,
    io::wia::{WIACompression, WIADisc},
};

pub struct Decompressor {
    pub kind: DecompressionKind,
    #[allow(unused)] // if compression features are disabled
    pub cache: DecompressorCache,
}

impl Clone for Decompressor {
    fn clone(&self) -> Self {
        Self { kind: self.kind.clone(), cache: DecompressorCache::default() }
    }
}

#[derive(Default)]
pub enum DecompressorCache {
    #[default]
    None,
    #[cfg(feature = "compress-zlib")]
    Deflate(Box<miniz_oxide::inflate::core::DecompressorOxide>),
    #[cfg(feature = "compress-zstd")]
    Zstandard(zstd_safe::DCtx<'static>),
}

impl Decompressor {
    pub fn new(kind: DecompressionKind) -> Self {
        Self { kind, cache: DecompressorCache::default() }
    }

    #[instrument(name = "Decompressor::decompress", skip_all)]
    pub fn decompress(&mut self, buf: &[u8], out: &mut [u8]) -> io::Result<usize> {
        match &self.kind {
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
            DecompressionKind::Deflate => {
                let decompressor = match &mut self.cache {
                    DecompressorCache::Deflate(decompressor) => decompressor,
                    _ => {
                        self.cache = DecompressorCache::Deflate(Box::new(
                            miniz_oxide::inflate::core::DecompressorOxide::new(),
                        ));
                        match &mut self.cache {
                            DecompressorCache::Deflate(decompressor) => decompressor,
                            _ => unreachable!(),
                        }
                    }
                };
                decompressor.init();
                let (status, in_size, out_size) = miniz_oxide::inflate::core::decompress(
                    decompressor.as_mut(),
                    buf,
                    out,
                    0,
                    miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
                        | miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
                );
                match status {
                    miniz_oxide::inflate::TINFLStatus::Done => Ok(out_size),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Deflate decompression status {:?} (in: {}, out: {})",
                            status, in_size, out_size
                        ),
                    )),
                }
            }
            #[cfg(feature = "compress-bzip2")]
            DecompressionKind::Bzip2 => {
                let mut decoder = bzip2::Decompress::new(false);
                let status = decoder.decompress(buf, out)?;
                match status {
                    bzip2::Status::StreamEnd => Ok(decoder.total_out() as usize),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bzip2 decompression status {:?}", status),
                    )),
                }
            }
            #[cfg(feature = "compress-lzma")]
            DecompressionKind::Lzma(data) => {
                use lzma_util::{lzma_props_decode, new_lzma_decoder};
                let mut decoder = new_lzma_decoder(&lzma_props_decode(data)?)?;
                let status = decoder.process(buf, out, liblzma::stream::Action::Finish)?;
                match status {
                    liblzma::stream::Status::StreamEnd => Ok(decoder.total_out() as usize),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("LZMA decompression status {:?}", status),
                    )),
                }
            }
            #[cfg(feature = "compress-lzma")]
            DecompressionKind::Lzma2(data) => {
                use lzma_util::{lzma2_props_decode, new_lzma2_decoder};
                let mut decoder = new_lzma2_decoder(&lzma2_props_decode(data)?)?;
                let status = decoder.process(buf, out, liblzma::stream::Action::Finish)?;
                match status {
                    liblzma::stream::Status::StreamEnd => Ok(decoder.total_out() as usize),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("LZMA2 decompression status {:?}", status),
                    )),
                }
            }
            #[cfg(feature = "compress-zstd")]
            DecompressionKind::Zstandard => {
                let ctx = match &mut self.cache {
                    DecompressorCache::Zstandard(ctx) => ctx,
                    _ => {
                        let ctx = zstd_safe::DCtx::create();
                        self.cache = DecompressorCache::Zstandard(ctx);
                        match &mut self.cache {
                            DecompressorCache::Zstandard(ctx) => ctx,
                            _ => unreachable!(),
                        }
                    }
                };
                ctx.decompress(out, buf).map_err(zstd_util::map_error_code)
            }
        }
    }

    pub fn get_content_size(&self, buf: &[u8]) -> io::Result<Option<usize>> {
        match &self.kind {
            DecompressionKind::None => Ok(Some(buf.len())),
            #[cfg(feature = "compress-zstd")]
            DecompressionKind::Zstandard => zstd_safe::get_frame_content_size(buf)
                .map(|n| n.map(|n| n as usize))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            #[allow(unreachable_patterns)] // if compression features are disabled
            _ => Ok(None),
        }
    }
}

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
}

pub struct Compressor {
    pub kind: Compression,
    pub cache: CompressorCache,
    pub buffer: Vec<u8>,
}

impl Clone for Compressor {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            cache: CompressorCache::default(),
            buffer: Vec::with_capacity(self.buffer.capacity()),
        }
    }
}

#[derive(Default)]
pub enum CompressorCache {
    #[default]
    None,
    #[cfg(feature = "compress-zlib")]
    Deflate(Box<miniz_oxide::deflate::core::CompressorOxide>),
    #[cfg(feature = "compress-zstd")]
    Zstandard(zstd_safe::CCtx<'static>),
}

impl Compressor {
    pub fn new(kind: Compression, buffer_size: usize) -> Self {
        Self { kind, cache: CompressorCache::default(), buffer: Vec::with_capacity(buffer_size) }
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
            Compression::Deflate(level) => {
                let compressor = match &mut self.cache {
                    CompressorCache::Deflate(compressor) => compressor,
                    _ => {
                        self.cache = CompressorCache::Deflate(Box::new(
                            miniz_oxide::deflate::core::CompressorOxide::new(
                                miniz_oxide::deflate::core::create_comp_flags_from_zip_params(
                                    level as i32,
                                    15,
                                    0,
                                ),
                            ),
                        ));
                        match &mut self.cache {
                            CompressorCache::Deflate(compressor) => compressor,
                            _ => unreachable!(),
                        }
                    }
                };
                self.buffer.resize(self.buffer.capacity(), 0);
                compressor.reset();
                let (status, _, out_size) = miniz_oxide::deflate::core::compress(
                    compressor.as_mut(),
                    buf,
                    self.buffer.as_mut_slice(),
                    miniz_oxide::deflate::core::TDEFLFlush::Finish,
                );
                self.buffer.truncate(out_size);
                Ok(status == miniz_oxide::deflate::core::TDEFLStatus::Done)
            }
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2(level) => {
                let compression = bzip2::Compression::new(level as u32);
                let mut compress = bzip2::Compress::new(compression, 30);
                let status = compress.compress_vec(buf, &mut self.buffer, bzip2::Action::Finish)?;
                Ok(status == bzip2::Status::StreamEnd)
            }
            #[cfg(feature = "compress-lzma")]
            Compression::Lzma(level) => {
                let options = liblzma::stream::LzmaOptions::new_preset(level as u32)?;
                let mut encoder = lzma_util::new_lzma_encoder(&options)?;
                let status =
                    encoder.process_vec(buf, &mut self.buffer, liblzma::stream::Action::Finish)?;
                Ok(status == liblzma::stream::Status::StreamEnd)
            }
            #[cfg(feature = "compress-lzma")]
            Compression::Lzma2(level) => {
                let options = liblzma::stream::LzmaOptions::new_preset(level as u32)?;
                let mut encoder = lzma_util::new_lzma2_encoder(&options)?;
                let status =
                    encoder.process_vec(buf, &mut self.buffer, liblzma::stream::Action::Finish)?;
                Ok(status == liblzma::stream::Status::StreamEnd)
            }
            #[cfg(feature = "compress-zstd")]
            Compression::Zstandard(level) => {
                let ctx = match &mut self.cache {
                    CompressorCache::Zstandard(compressor) => compressor,
                    _ => {
                        let mut ctx = zstd_safe::CCtx::create();
                        ctx.init(level as i32).map_err(zstd_util::map_error_code)?;
                        ctx.set_parameter(zstd_safe::CParameter::ContentSizeFlag(true))
                            .map_err(zstd_util::map_error_code)?;
                        self.cache = CompressorCache::Zstandard(ctx);
                        match &mut self.cache {
                            CompressorCache::Zstandard(compressor) => compressor,
                            _ => unreachable!(),
                        }
                    }
                };
                match ctx.compress2(&mut self.buffer, buf) {
                    Ok(_) => Ok(true),
                    // dstSize_tooSmall
                    Err(e) if e == -70isize as usize => Ok(false),
                    Err(e) => Err(zstd_util::map_error_code(e)),
                }
            }
            #[allow(unreachable_patterns)] // if compression is disabled
            _ => Err(io::Error::other(format!("Unsupported compression: {:?}", self.kind))),
        }
    }
}

#[cfg(feature = "compress-lzma")]
pub mod lzma_util {
    use std::{
        cmp::Ordering,
        io::{Error, ErrorKind, Result},
    };

    use liblzma::stream::{Filters, LzmaOptions, Stream};

    use crate::util::{array_ref, array_ref_mut, static_assert};

    /// Decodes the LZMA Properties byte (lc/lp/pb).
    /// See `lzma_lzma_lclppb_decode` in `liblzma/lzma/lzma_decoder.c`.
    pub fn lzma_lclppb_decode(options: &mut LzmaOptions, byte: u8) -> Result<()> {
        let mut d = byte as u32;
        if d >= (9 * 5 * 5) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid LZMA props byte: {}", d),
            ));
        }
        options.literal_context_bits(d % 9);
        d /= 9;
        options.position_bits(d / 5);
        options.literal_position_bits(d % 5);
        Ok(())
    }

    /// Encodes the LZMA Properties byte (lc/lp/pb).
    /// See `lzma_lzma_lclppb_encode` in `liblzma/lzma/lzma_encoder.c`.
    pub fn lzma_lclppb_encode(options: &LzmaOptions) -> Result<u8> {
        let options = get_options_sys(options);
        let byte = (options.pb * 5 + options.lp) * 9 + options.lc;
        if byte >= (9 * 5 * 5) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid LZMA props byte: {}", byte),
            ));
        }
        Ok(byte as u8)
    }

    /// Decodes LZMA properties.
    /// See `lzma_lzma_props_decode` in `liblzma/lzma/lzma_decoder.c`.
    pub fn lzma_props_decode(props: &[u8]) -> Result<LzmaOptions> {
        if props.len() != 5 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid LZMA props length: {}", props.len()),
            ));
        }
        let mut options = LzmaOptions::new();
        lzma_lclppb_decode(&mut options, props[0])?;
        options.dict_size(u32::from_le_bytes(*array_ref![props, 1, 4]));
        Ok(options)
    }

    /// Encodes LZMA properties.
    /// See `lzma_lzma_props_encode` in `liblzma/lzma/lzma_encoder.c`.
    pub fn lzma_props_encode(options: &LzmaOptions) -> Result<[u8; 5]> {
        let mut props = [0u8; 5];
        props[0] = lzma_lclppb_encode(options)?;
        *array_ref_mut![props, 1, 4] = get_options_sys(options).dict_size.to_le_bytes();
        Ok(props)
    }

    /// Decodes LZMA2 properties.
    /// See `lzma_lzma2_props_decode` in `liblzma/lzma/lzma2_decoder.c`.
    pub fn lzma2_props_decode(props: &[u8]) -> Result<LzmaOptions> {
        if props.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid LZMA2 props length: {}", props.len()),
            ));
        }
        let d = props[0] as u32;
        let mut options = LzmaOptions::new();
        options.dict_size(match d.cmp(&40) {
            Ordering::Greater => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid LZMA2 props byte: {}", d),
                ));
            }
            Ordering::Equal => u32::MAX,
            Ordering::Less => (2 | (d & 1)) << (d / 2 + 11),
        });
        Ok(options)
    }

    /// Encodes LZMA2 properties.
    /// See `lzma_lzma2_props_encode` in `liblzma/lzma/lzma2_encoder.c`.
    pub fn lzma2_props_encode(options: &LzmaOptions) -> Result<[u8; 1]> {
        let options = get_options_sys(options);
        let mut d = options.dict_size.max(liblzma_sys::LZMA_DICT_SIZE_MIN);

        // Round up to the next 2^n - 1 or 2^n + 2^(n - 1) - 1 depending
        // on which one is the next:
        d -= 1;
        d |= d >> 2;
        d |= d >> 3;
        d |= d >> 4;
        d |= d >> 8;
        d |= d >> 16;

        // Get the highest two bits using the proper encoding:
        if d == u32::MAX {
            d = 40;
        } else {
            d = get_dist_slot(d + 1) - 24;
        }

        Ok([d as u8])
    }

    /// Creates a new raw LZMA decoder with the given options.
    pub fn new_lzma_decoder(options: &LzmaOptions) -> Result<Stream> {
        let mut filters = Filters::new();
        filters.lzma1(options);
        Stream::new_raw_decoder(&filters).map_err(Error::from)
    }

    /// Creates a new raw LZMA encoder with the given options.
    pub fn new_lzma_encoder(options: &LzmaOptions) -> Result<Stream> {
        let mut filters = Filters::new();
        filters.lzma1(options);
        Stream::new_raw_encoder(&filters).map_err(Error::from)
    }

    /// Creates a new raw LZMA2 decoder with the given options.
    pub fn new_lzma2_decoder(options: &LzmaOptions) -> Result<Stream> {
        let mut filters = Filters::new();
        filters.lzma2(options);
        Stream::new_raw_decoder(&filters).map_err(Error::from)
    }

    /// Creates a new raw LZMA2 encoder with the given options.
    pub fn new_lzma2_encoder(options: &LzmaOptions) -> Result<Stream> {
        let mut filters = Filters::new();
        filters.lzma2(options);
        Stream::new_raw_encoder(&filters).map_err(Error::from)
    }

    /// liblzma does not expose any accessors for `LzmaOptions`, so we have to
    /// cast it into the internal `lzma_options_lzma` struct.
    #[inline]
    fn get_options_sys(options: &LzmaOptions) -> &liblzma_sys::lzma_options_lzma {
        static_assert!(size_of::<LzmaOptions>() == size_of::<liblzma_sys::lzma_options_lzma>());
        unsafe { &*(options as *const LzmaOptions as *const liblzma_sys::lzma_options_lzma) }
    }

    /// See `get_dist_slot` in `liblzma/lzma/fastpos.h`.
    fn get_dist_slot(dist: u32) -> u32 {
        if dist <= 4 {
            dist
        } else {
            let i = dist.leading_zeros() ^ 31;
            (i + i) + ((dist >> (i - 1)) & 1)
        }
    }
}

#[cfg(feature = "compress-zstd")]
mod zstd_util {
    use std::io;

    pub fn map_error_code(code: usize) -> io::Error {
        io::Error::other(zstd_safe::get_error_name(code))
    }
}
