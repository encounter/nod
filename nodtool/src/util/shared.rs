use std::{
    cmp::min,
    fmt,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::{mpsc::sync_channel, Arc},
    thread,
};

use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use nod::{Compression, Disc, DiscHeader, DiscMeta, OpenOptions, Result, ResultContext};
use size::Size;
use zerocopy::FromZeros;

use crate::util::{
    digest::{digest_thread, DigestResult},
    display, redump,
};

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
        meta.crc32.is_some()
            || meta.md5.is_some()
            || meta.sha1.is_some()
            || meta.xxhash64.is_some()
    );
    println!();
    println!("Title: {}", header.game_title_str());
    println!("Game ID: {}", header.game_id_str());
    println!("Disc {}, Revision {}", header.disc_num + 1, header.disc_version);
    if !header.has_partition_hashes() {
        println!("[!] Disc has no hashes");
    }
    if !header.has_partition_encryption() {
        println!("[!] Disc is not encrypted");
    }
}

pub fn convert_and_verify(
    in_file: &Path,
    out_file: Option<&Path>,
    md5: bool,
    options: &OpenOptions,
) -> Result<()> {
    println!("Loading {}", display(in_file));
    let mut disc = Disc::new_with_options(in_file, options)?;
    let header = disc.header();
    let meta = disc.meta();
    print_header(header, &meta);

    let disc_size = disc.disc_size();

    let mut file = if let Some(out_file) = out_file {
        Some(
            File::create(out_file)
                .with_context(|| format!("Creating file {}", display(out_file)))?,
        )
    } else {
        None
    };

    if out_file.is_some() {
        println!("\nConverting...");
    } else {
        println!("\nVerifying...");
    }
    let pb = ProgressBar::new(disc_size);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn fmt::Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"));

    const BUFFER_SIZE: usize = 1015808; // LCM(0x8000, 0x7C00)
    let digest_threads = if md5 {
        vec![
            digest_thread::<crc32fast::Hasher>(),
            digest_thread::<md5::Md5>(),
            digest_thread::<sha1::Sha1>(),
            digest_thread::<xxhash_rust::xxh64::Xxh64>(),
        ]
    } else {
        vec![
            digest_thread::<crc32fast::Hasher>(),
            digest_thread::<sha1::Sha1>(),
            digest_thread::<xxhash_rust::xxh64::Xxh64>(),
        ]
    };

    let (w_tx, w_rx) = sync_channel::<Arc<[u8]>>(1);
    let w_thread = thread::spawn(move || {
        let mut total_written = 0u64;
        while let Ok(data) = w_rx.recv() {
            if let Some(file) = &mut file {
                file.write_all(data.as_ref())
                    .with_context(|| {
                        format!("Writing {} bytes at offset {}", data.len(), total_written)
                    })
                    .unwrap();
            }
            total_written += data.len() as u64;
            pb.set_position(total_written);
        }
        if let Some(mut file) = file {
            file.flush().context("Flushing output file").unwrap();
        }
        pb.finish();
    });

    let mut total_read = 0u64;
    let mut buf = <[u8]>::new_box_zeroed_with_elems(BUFFER_SIZE)?;
    while total_read < disc_size {
        let read = min(BUFFER_SIZE as u64, disc_size - total_read) as usize;
        disc.read_exact(&mut buf[..read]).with_context(|| {
            format!("Reading {} bytes at disc offset {}", BUFFER_SIZE, total_read)
        })?;

        let arc = Arc::<[u8]>::from(&buf[..read]);
        for (tx, _) in &digest_threads {
            tx.send(arc.clone()).map_err(|_| "Sending data to hash thread")?;
        }
        w_tx.send(arc).map_err(|_| "Sending data to write thread")?;
        total_read += read as u64;
    }
    drop(w_tx); // Close channel
    w_thread.join().unwrap();

    println!();
    if let Some(path) = out_file {
        println!("Wrote {} to {}", Size::from_bytes(total_read), display(path));
    }

    println!();
    let mut crc32 = None;
    let mut md5 = None;
    let mut sha1 = None;
    let mut xxh64 = None;
    for (tx, handle) in digest_threads {
        drop(tx); // Close channel
        match handle.join().unwrap() {
            DigestResult::Crc32(v) => crc32 = Some(v),
            DigestResult::Md5(v) => md5 = Some(v),
            DigestResult::Sha1(v) => sha1 = Some(v),
            DigestResult::Xxh64(v) => xxh64 = Some(v),
        }
    }

    let redump_entry = crc32.and_then(redump::find_by_crc32);
    let expected_crc32 = meta.crc32.or(redump_entry.as_ref().map(|e| e.crc32));
    let expected_md5 = meta.md5.or(redump_entry.as_ref().map(|e| e.md5));
    let expected_sha1 = meta.sha1.or(redump_entry.as_ref().map(|e| e.sha1));
    let expected_xxh64 = meta.xxhash64;

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

    if let Some(entry) = &redump_entry {
        let mut full_match = true;
        if let Some(md5) = md5 {
            if entry.md5 != md5 {
                full_match = false;
            }
        }
        if let Some(sha1) = sha1 {
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
    if let Some(crc32) = crc32 {
        print_digest(DigestResult::Crc32(crc32), expected_crc32.map(DigestResult::Crc32));
    }
    if let Some(md5) = md5 {
        print_digest(DigestResult::Md5(md5), expected_md5.map(DigestResult::Md5));
    }
    if let Some(sha1) = sha1 {
        print_digest(DigestResult::Sha1(sha1), expected_sha1.map(DigestResult::Sha1));
    }
    if let Some(xxh64) = xxh64 {
        print_digest(DigestResult::Xxh64(xxh64), expected_xxh64.map(DigestResult::Xxh64));
    }
    Ok(())
}
