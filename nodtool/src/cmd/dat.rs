use std::{
    cmp::min,
    collections::BTreeMap,
    fmt,
    io::Read,
    path::{Path, PathBuf},
    sync::{mpsc::sync_channel, Arc},
    thread,
};

use argp::FromArgs;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use nod::{Disc, OpenOptions, PartitionEncryptionMode, Result, ResultContext};
use zerocopy::FromZeros;

use crate::util::{
    digest::{digest_thread, DigestResult},
    redump,
    redump::GameResult,
};

#[derive(FromArgs, Debug)]
/// Commands related to DAT files.
#[argp(subcommand, name = "dat")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
pub enum SubCommand {
    Check(CheckArgs),
}

#[derive(FromArgs, Debug)]
/// Verify a collection of disc images against DAT files.
#[argp(subcommand, name = "check")]
pub struct CheckArgs {
    #[argp(positional)]
    /// disc image directory
    dir: PathBuf,
    #[argp(option, short = 'd')]
    /// path to DAT file(s)
    dat: Vec<PathBuf>,
    #[argp(switch)]
    /// rename files to match DAT entries
    rename: bool,
    #[argp(switch)]
    /// don't use embedded hashes if available
    full_verify: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Check(c_args) => check(c_args),
    }
}

fn check(args: CheckArgs) -> Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    let mut disc_results = BTreeMap::<u32, DiscResult>::new();
    let mut rename_map = BTreeMap::<PathBuf, PathBuf>::new();
    for entry in std::fs::read_dir(&args.dir).context("Opening ROM directory")? {
        let entry = entry.context("Reading ROM directory entry")?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            match load_disc(&path, &name, args.full_verify) {
                Ok(hashes) => {
                    let redump_entry = redump::find_by_crc32(hashes.crc32);
                    if let Some(entry) = &redump_entry {
                        let mut full_match = true;
                        if entry.sha1 != hashes.sha1 {
                            full_match = false;
                        }
                        if full_match {
                            println!("{}: ✅ {}", name, entry.name);
                        } else {
                            println!("{}: ❓ {} (partial match)", name, entry.name);
                        }
                        if entry.name != path.file_stem().unwrap() {
                            let file_name = if let Some(ext) = path.extension() {
                                format!("{}.{}", entry.name, ext.to_string_lossy())
                            } else {
                                entry.name.to_string()
                            };
                            rename_map.insert(path.clone(), path.with_file_name(file_name));
                        }
                        disc_results.insert(hashes.crc32, DiscResult {
                            name,
                            // hashes,
                            redump_entry: Some(entry.clone()),
                            matched: full_match,
                        });
                    } else {
                        println!("{}: ❌ Not found", name);
                        disc_results.insert(hashes.crc32, DiscResult {
                            name,
                            // hashes,
                            redump_entry: None,
                            matched: false,
                        });
                    }
                }
                Err(e) => println!("{}: ❌ Error: {}", name, e),
            }
        }
    }
    println!();
    let mut matched_count = 0usize;
    let mut missing_count = 0usize;
    let mut mismatch_count = 0usize;
    let mut total_count = 0usize;
    let mut extra_count = 0usize;
    for entry in redump::EntryIter::new() {
        if let Some(result) = disc_results.get(&entry.crc32) {
            if result.matched {
                matched_count += 1;
            } else {
                println!("❓ Mismatched: {}", entry.name);
                mismatch_count += 1;
            }
        } else {
            println!("❌ Missing: {}", entry.name);
            missing_count += 1;
        }
        total_count += 1;
    }
    for result in disc_results.values() {
        if !result.matched && result.redump_entry.is_none() {
            println!("❓ Unmatched: {}", result.name);
            extra_count += 1;
        }
    }
    println!(
        "Matched: {}, Missing: {}, Mismatched: {}, Total: {}",
        matched_count, missing_count, mismatch_count, total_count
    );
    println!("Unmatched: {}", extra_count);

    if args.rename && !rename_map.is_empty() {
        println!("\nRenaming files...");
        for (old_path, new_path) in rename_map {
            println!("{} -> {}", old_path.display(), new_path.display());
            std::fs::rename(&old_path, &new_path).context("Renaming file")?;
        }
    }
    Ok(())
}

struct DiscResult {
    pub name: String,
    // pub hashes: DiscHashes,
    pub redump_entry: Option<GameResult<'static>>,
    pub matched: bool,
}

struct DiscHashes {
    pub crc32: u32,
    pub sha1: [u8; 20],
}

fn load_disc(path: &Path, name: &str, full_verify: bool) -> Result<DiscHashes> {
    let options = OpenOptions { partition_encryption: PartitionEncryptionMode::Original };
    let mut disc = Disc::new_with_options(path, &options)?;
    let disc_size = disc.disc_size();
    if !full_verify {
        let meta = disc.meta();
        if let (Some(crc32), Some(sha1)) = (meta.crc32, meta.sha1) {
            return Ok(DiscHashes { crc32, sha1 });
        }
    }

    let pb = ProgressBar::new(disc_size).with_message(format!("{}:", name));
    pb.set_style(ProgressStyle::with_template("{msg} {spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn fmt::Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"));

    const BUFFER_SIZE: usize = 1015808; // LCM(0x8000, 0x7C00)
    let digest_threads = [digest_thread::<crc32fast::Hasher>(), digest_thread::<sha1::Sha1>()];

    let (w_tx, w_rx) = sync_channel::<Arc<[u8]>>(1);
    let w_thread = thread::spawn(move || {
        let mut total_written = 0u64;
        while let Ok(data) = w_rx.recv() {
            total_written += data.len() as u64;
            pb.set_position(total_written);
        }
        pb.finish_and_clear();
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

    let mut crc32 = None;
    let mut sha1 = None;
    for (tx, handle) in digest_threads {
        drop(tx); // Close channel
        match handle.join().unwrap() {
            DigestResult::Crc32(v) => crc32 = Some(v),
            DigestResult::Sha1(v) => sha1 = Some(v),
            _ => {}
        }
    }

    Ok(DiscHashes { crc32: crc32.unwrap(), sha1: sha1.unwrap() })
}
