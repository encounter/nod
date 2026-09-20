//! In-memory disc conversion smoke test, runnable natively or in a WASM engine.
use std::io::{Cursor, Read};

use nod::{
    common::{Compression, Format},
    disc::{GCN_MAGIC, SECTOR_SIZE},
    read::{DiscOptions, DiscReader},
    write::{DiscWriter, FormatOptions, ProcessOptions},
};

fn main() {
    let mut iso = vec![0; 8 * SECTOR_SIZE];
    iso[..6].copy_from_slice(b"GTEST0");
    iso[0x1c..0x20].copy_from_slice(&GCN_MAGIC);
    // A minimal FST containing only the root directory.
    iso[0x424..0x428].copy_from_slice(&0x3000u32.to_be_bytes());
    iso[0x428..0x42c].copy_from_slice(&13u32.to_be_bytes());
    iso[0x3000] = 1;
    iso[0x3008..0x300c].copy_from_slice(&1u32.to_be_bytes());
    for (i, byte) in iso[SECTOR_SIZE..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    for (format, compression) in [
        (Format::Iso, Compression::None),
        #[cfg(feature = "compress-zlib")]
        (Format::Gcz, Compression::Deflate(6)),
        #[cfg(feature = "compress-bzip2")]
        (Format::Wia, Compression::Bzip2(6)),
        #[cfg(feature = "compress-lzma")]
        (Format::Wia, Compression::Lzma(6)),
        #[cfg(feature = "compress-lzma")]
        (Format::Rvz, Compression::Lzma2(6)),
        #[cfg(feature = "compress-zstd")]
        (Format::Rvz, Compression::Zstandard(19)),
    ] {
        let disc =
            DiscReader::new_from_cloneable_read(Cursor::new(iso.clone()), &DiscOptions::default())
                .unwrap();
        let writer = DiscWriter::new(disc, &FormatOptions {
            format,
            compression,
            block_size: format.default_block_size(),
        })
        .unwrap();
        let mut encoded = Vec::new();
        let finalization = writer
            .process(
                |bytes, _, _| {
                    encoded.extend_from_slice(&bytes);
                    Ok(())
                },
                &ProcessOptions {
                    digest_crc32: true,
                    digest_md5: true,
                    digest_sha1: true,
                    digest_xxh64: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(finalization.crc32, Some(crc32fast::hash(&iso)));
        assert!(finalization.md5.is_some());
        assert!(finalization.sha1.is_some());
        assert!(finalization.xxh64.is_some());
        encoded[..finalization.header.len()].copy_from_slice(&finalization.header);
        let mut decoded =
            DiscReader::new_from_cloneable_read(Cursor::new(encoded), &DiscOptions::default())
                .unwrap();
        let mut out = Vec::new();
        decoded.read_to_end(&mut out).unwrap();
        assert_eq!(out, iso, "{format:?} / {compression:?}");
    }
}
