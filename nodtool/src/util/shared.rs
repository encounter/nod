use std::{
    fmt,
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use nod::{
    common::Compression,
    disc::DiscHeader,
    read::{DiscMeta, DiscOptions, DiscReader, PartitionEncryption},
    write::{DiscWriter, DiscWriterWeight, FormatOptions, ProcessOptions},
    Result, ResultContext,
};
use size::Size;

use crate::util::{digest::DigestResult, path_display, redump};

pub fn print_header(header: &DiscHeader, meta: &DiscMeta) {
    println!("Format: {}", meta.format);
    if meta.compression != Compression::None {
        println!("Compression: {}", meta.compression);
    }
    if let Some(block_size) = meta.block_size {
        println!("Block size: {}", Size::from_bytes(block_size));
    }
    println!("Lossless: {}", meta.lossless);
    println!(
        "Verification data: {}",
        meta.crc32.is_some() || meta.md5.is_some() || meta.sha1.is_some() || meta.xxh64.is_some()
    );
    println!();
    println!("Title: {}", header.game_title_str());
    println!("Game ID: {}", header.game_id_str());
    println!("Disc {}, Revision {}", header.disc_num + 1, header.disc_version);
    if !header.has_partition_encryption() {
        println!("[!] Disc is not encrypted");
    }
    if !header.has_partition_hashes() {
        println!("[!] Disc has no hashes");
    }
}

pub fn convert_and_verify(
    in_file: &Path,
    out_file: Option<&Path>,
    md5: bool,
    options: &DiscOptions,
    format_options: &FormatOptions,
) -> Result<()> {
    println!("Loading {}", path_display(in_file));
    let disc = DiscReader::new(in_file, options)?;
    let header = disc.header();
    let meta = disc.meta();
    print_header(header, &meta);

    let mut file = if let Some(out_file) = out_file {
        Some(
            File::create(out_file)
                .with_context(|| format!("Creating file {}", path_display(out_file)))?,
        )
    } else {
        None
    };

    if out_file.is_some() {
        match options.partition_encryption {
            PartitionEncryption::ForceEncrypted => {
                println!("\nConverting to {} (encrypted)...", format_options.format)
            }
            PartitionEncryption::ForceDecrypted => {
                println!("\nConverting to {} (decrypted)...", format_options.format)
            }
            _ => println!("\nConverting to {}...", format_options.format),
        }
        if format_options.compression != Compression::None {
            println!("Compression: {}", format_options.compression);
        }
        if format_options.block_size > 0 {
            println!("Block size: {}", Size::from_bytes(format_options.block_size));
        }
    } else {
        match options.partition_encryption {
            PartitionEncryption::ForceEncrypted => {
                println!("\nVerifying (encrypted)...")
            }
            PartitionEncryption::ForceDecrypted => {
                println!("\nVerifying (decrypted)...")
            }
            _ => println!("\nVerifying..."),
        }
    }
    let disc_writer = DiscWriter::new(disc, format_options)?;
    let pb = ProgressBar::new(disc_writer.progress_bound());
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn fmt::Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"));

    let cpus = num_cpus::get();
    let processor_threads = match disc_writer.weight() {
        DiscWriterWeight::Light => 0,
        DiscWriterWeight::Medium => cpus / 2,
        DiscWriterWeight::Heavy => cpus,
    };

    let mut total_written = 0u64;
    let finalization = disc_writer.process(
        |data, pos, _| {
            if let Some(file) = &mut file {
                file.write_all(data.as_ref())?;
            }
            total_written += data.len() as u64;
            pb.set_position(pos);
            Ok(())
        },
        &ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: md5,
            digest_sha1: true,
            digest_xxh64: true,
        },
    )?;
    pb.finish();

    // Finalize disc writer
    if !finalization.header.is_empty() {
        if let Some(file) = &mut file {
            file.seek(SeekFrom::Start(0)).context("Seeking to start of output file")?;
            file.write_all(finalization.header.as_ref()).context("Writing header")?;
        } else {
            return Err(nod::Error::Other("No output file, but requires finalization".to_string()));
        }
    }
    if let Some(mut file) = file {
        file.flush().context("Flushing output file")?;
    }

    println!();
    if let Some(path) = out_file {
        println!("Wrote {} to {}", Size::from_bytes(total_written), path_display(path));
    }
    println!();

    let mut redump_entry = None;
    let mut expected_crc32 = None;
    let mut expected_md5 = None;
    let mut expected_sha1 = None;
    let mut expected_xxh64 = None;
    if options.partition_encryption == PartitionEncryption::Original {
        // Use verification data in disc and check redump
        redump_entry = finalization.crc32.and_then(redump::find_by_crc32);
        expected_crc32 = meta.crc32.or(redump_entry.as_ref().map(|e| e.crc32));
        expected_md5 = meta.md5.or(redump_entry.as_ref().map(|e| e.md5));
        expected_sha1 = meta.sha1.or(redump_entry.as_ref().map(|e| e.sha1));
        expected_xxh64 = meta.xxh64;
    } else if options.partition_encryption == PartitionEncryption::ForceEncrypted {
        // Ignore verification data in disc, but still check redump
        redump_entry = finalization.crc32.and_then(redump::find_by_crc32);
        expected_crc32 = redump_entry.as_ref().map(|e| e.crc32);
        expected_md5 = redump_entry.as_ref().map(|e| e.md5);
        expected_sha1 = redump_entry.as_ref().map(|e| e.sha1);
    }

    fn print_digest(value: DigestResult, expected: Option<DigestResult>) {
        print!("{:<6}: ", value.name());
        if let Some(expected) = expected {
            if expected != value {
                print!("{} ❌ (expected: {})", value, expected);
            } else {
                print!("{} ✅", value);
            }
        } else {
            print!("{}", value);
        }
        println!();
    }

    if let Some(crc32) = finalization.crc32 {
        if let Some(entry) = &redump_entry {
            let mut full_match = true;
            if let Some(md5) = finalization.md5 {
                if entry.md5 != md5 {
                    full_match = false;
                }
            }
            if let Some(sha1) = finalization.sha1 {
                if entry.sha1 != sha1 {
                    full_match = false;
                }
            }
            if full_match {
                println!("Redump: {} ✅", entry.name);
            } else {
                println!("Redump: {} ❓ (partial match)", entry.name);
            }
        } else {
            println!("Redump: Not found ❌");
        }
        print_digest(DigestResult::Crc32(crc32), expected_crc32.map(DigestResult::Crc32));
    }
    if let Some(md5) = finalization.md5 {
        print_digest(DigestResult::Md5(md5), expected_md5.map(DigestResult::Md5));
    }
    if let Some(sha1) = finalization.sha1 {
        print_digest(DigestResult::Sha1(sha1), expected_sha1.map(DigestResult::Sha1));
    }
    if let Some(xxh64) = finalization.xxh64 {
        print_digest(DigestResult::Xxh64(xxh64), expected_xxh64.map(DigestResult::Xxh64));
    }
    Ok(())
}
