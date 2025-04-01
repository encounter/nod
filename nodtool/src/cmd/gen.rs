use std::{
    fs,
    fs::File,
    io,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::from_utf8,
    time::Instant,
};

use argp::FromArgs;
use nod::{
    ResultContext,
    build::gc::{FileCallback, FileInfo, GCPartitionBuilder, PartitionOverrides},
    common::PartitionKind,
    disc::{
        BB2_OFFSET, BI2_SIZE, BOOT_SIZE, BootHeader, DiscHeader, MINI_DVD_SIZE, SECTOR_SIZE,
        fst::Fst,
    },
    read::{
        DiscOptions, DiscReader, PartitionEncryption, PartitionMeta, PartitionOptions,
        PartitionReader,
    },
    util::{buf_copy, lfg::LaggedFibonacci},
    write::{DiscWriter, FormatOptions, ProcessOptions},
};
use tracing::{debug, error, info, warn};
use zerocopy::{FromBytes, FromZeros};

use crate::util::{array_ref, redump, shared::convert_and_verify};

#[derive(FromArgs, Debug)]
/// Generates a disc image.
#[argp(subcommand, name = "gen")]
pub struct Args {
    #[argp(positional)]
    /// Path to extracted disc image
    dir: PathBuf,
    #[argp(positional)]
    /// Output ISO file
    out: PathBuf,
}

#[derive(FromArgs, Debug)]
/// Test disc image generation.
#[argp(subcommand, name = "gentest")]
pub struct TestArgs {
    #[argp(positional)]
    /// Path to original disc images
    inputs: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// Output ISO file
    output: Option<PathBuf>,
    #[argp(option, short = 't')]
    /// Output original ISO for comparison
    test_output: Option<PathBuf>,
}

fn read_fixed<const N: usize>(path: &Path) -> nod::Result<Box<[u8; N]>> {
    let mut buf = <[u8; N]>::new_box_zeroed()?;
    File::open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?
        .read_exact(buf.as_mut())
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(buf)
}

fn read_all(path: &Path) -> nod::Result<Box<[u8]>> {
    let mut buf = Vec::new();
    File::open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?
        .read_to_end(&mut buf)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(buf.into_boxed_slice())
}

struct FileWriteInfo {
    name: String,
    offset: u64,
    length: u64,
}

fn file_size(path: &Path) -> nod::Result<u64> {
    Ok(fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for {}", path.display()))?
        .len())
}

fn check_file_size(path: &Path, expected: u64) -> nod::Result<()> {
    let actual = file_size(path)?;
    if actual != expected {
        return Err(nod::Error::DiscFormat(format!(
            "File {} has size {}, expected {}",
            path.display(),
            actual,
            expected
        )));
    }
    Ok(())
}

pub fn run(args: Args) -> nod::Result<()> {
    let start = Instant::now();

    // Validate file sizes
    let boot_path = args.dir.join("sys/boot.bin");
    check_file_size(&boot_path, BOOT_SIZE as u64)?;
    let bi2_path = args.dir.join("sys/bi2.bin");
    check_file_size(&bi2_path, BI2_SIZE as u64)?;
    let apploader_path = args.dir.join("sys/apploader.img");
    let apploader_size = file_size(&apploader_path)?;
    let dol_path = args.dir.join("sys/main.dol");
    let dol_size = file_size(&dol_path)?;

    // Build metadata
    let mut file_infos = Vec::new();
    let boot_data: Box<[u8; BOOT_SIZE]> = read_fixed(&boot_path)?;
    let header = DiscHeader::ref_from_bytes(array_ref![boot_data, 0, size_of::<DiscHeader>()])
        .expect("Failed to read disc header");
    let junk_id = get_junk_id(header);
    let boot_header =
        BootHeader::ref_from_bytes(array_ref![boot_data, BB2_OFFSET, size_of::<BootHeader>()])
            .expect("Failed to read boot header");
    let fst_path = args.dir.join("sys/fst.bin");
    let fst_data = read_all(&fst_path)?;
    let fst = Fst::new(&fst_data).expect("Failed to parse FST");

    file_infos.push(FileWriteInfo {
        name: "sys/boot.bin".to_string(),
        offset: 0,
        length: BOOT_SIZE as u64,
    });
    file_infos.push(FileWriteInfo {
        name: "sys/bi2.bin".to_string(),
        offset: BOOT_SIZE as u64,
        length: BI2_SIZE as u64,
    });
    file_infos.push(FileWriteInfo {
        name: "sys/apploader.img".to_string(),
        offset: BOOT_SIZE as u64 + BI2_SIZE as u64,
        length: apploader_size,
    });
    let fst_offset = boot_header.fst_offset(false);
    let dol_offset = boot_header.dol_offset(false);
    if dol_offset < fst_offset {
        file_infos.push(FileWriteInfo {
            name: "sys/main.dol".to_string(),
            offset: dol_offset,
            length: dol_size,
        });
    } else {
        let mut found = false;
        for (_, node, path) in fst.iter() {
            if !node.is_file() {
                continue;
            }
            let offset = node.offset(false);
            if offset == dol_offset {
                info!("Using DOL from FST: {}", path);
                found = true;
            }
        }
        if !found {
            return Err(nod::Error::DiscFormat("DOL not found in FST".to_string()));
        }
    }
    let fst_size = boot_header.fst_size(false);
    file_infos.push(FileWriteInfo {
        name: "sys/fst.bin".to_string(),
        offset: fst_offset,
        length: fst_size,
    });

    // Collect files
    for (_, node, path) in fst.iter() {
        let length = node.length() as u64;
        if node.is_dir() {
            continue;
        }

        let mut file_path = args.dir.join("files");
        file_path.extend(path.split('/'));
        let metadata = match fs::metadata(&file_path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                warn!("File not found: {}", file_path.display());
                continue;
            }
            Err(e) => {
                return Err(e)
                    .context(format!("Failed to get metadata for {}", file_path.display()));
            }
        };
        if metadata.is_dir() {
            return Err(nod::Error::Other(format!("Path {} is a directory", file_path.display())));
        }
        if metadata.len() != length {
            return Err(nod::Error::Other(format!(
                "File {} has size {}, expected {}",
                file_path.display(),
                metadata.len(),
                length
            )));
        }
        let offset = node.offset(false);
        file_infos.push(FileWriteInfo {
            name: file_path.into_os_string().into_string().unwrap(),
            offset,
            length,
        });
    }
    sort_files(&mut file_infos)?;

    // Write files
    let mut out = File::create(&args.out)
        .with_context(|| format!("Failed to create {}", args.out.display()))?;
    info!("Writing disc image to {} ({} files)", args.out.display(), file_infos.len());
    let crc =
        write_files(&mut out, &file_infos, header, boot_header, junk_id, |out, name| match name {
            "sys/boot.bin" => out.write_all(boot_data.as_ref()),
            "sys/fst.bin" => out.write_all(fst_data.as_ref()),
            path => {
                let mut in_file = File::open(args.dir.join(path))?;
                io::copy(&mut in_file, out).map(|_| ())
            }
        })?;
    out.flush().context("Failed to flush output file")?;
    info!("Generated disc image in {:?} (CRC32: {:08X})", start.elapsed(), crc);
    let redump_entry = redump::find_by_crc32(crc);
    if let Some(entry) = &redump_entry {
        println!("Redump: {} ✅", entry.name);
    } else {
        println!("Redump: Not found ❌");
    }
    Ok(())
}

#[inline]
fn align_up<const N: u64>(n: u64) -> u64 { (n + N - 1) & !(N - 1) }

#[inline]
fn gcm_align(n: u64) -> u64 { (n + 31) & !3 }

/// Files can be located on the inner rim of the disc (closer to the center) or the outer rim
/// (closer to the edge). The inner rim is slower to read, so developers often configured certain
/// files to be located on the outer rim. This function attempts to find a gap in the file offsets
/// between the inner and outer rim, which we need to recreate junk data properly.
fn find_file_gap(file_infos: &[FileWriteInfo], fst_end: u64) -> Option<u64> {
    let mut last_offset = 0;
    for info in file_infos {
        if last_offset > fst_end && info.offset > last_offset + SECTOR_SIZE as u64 {
            debug!("Found file gap at {:X} -> {:X}", last_offset, info.offset);
            return Some(last_offset);
        }
        last_offset = info.offset + info.length;
    }
    None
}

fn write_files<W>(
    w: &mut W,
    file_infos: &[FileWriteInfo],
    header: &DiscHeader,
    boot_header: &BootHeader,
    junk_id: Option<[u8; 4]>,
    mut callback: impl FnMut(&mut HashStream<&mut W>, &str) -> io::Result<()>,
) -> nod::Result<u32>
where
    W: Write + ?Sized,
{
    let fst_end = boot_header.fst_offset(false) + boot_header.fst_size(false);
    let file_gap = find_file_gap(file_infos, fst_end);
    let mut lfg = LaggedFibonacci::default();
    let mut out = HashStream::new(w);
    let mut last_end = 0;
    for info in file_infos {
        if let Some(junk_id) = junk_id {
            let aligned_end = gcm_align(last_end);
            if info.offset > aligned_end && last_end >= fst_end {
                // Junk data is aligned to 4 bytes with a 28 byte padding (aka `(n + 31) & !3`)
                // but a few cases don't have the 28 byte padding. Namely, the junk data after the
                // FST, and the junk data in between the inner and outer rim files. This attempts to
                // determine the correct alignment, but is not 100% accurate.
                let junk_start =
                    if file_gap == Some(last_end) { align_up::<4>(last_end) } else { aligned_end };
                debug!("Writing junk data at {:X} -> {:X}", junk_start, info.offset);
                write_junk_data(
                    &mut lfg,
                    &mut out,
                    junk_id,
                    header.disc_num,
                    junk_start,
                    info.offset,
                )?;
            }
        }
        debug!(
            "Writing file {} at {:X} -> {:X}",
            info.name,
            info.offset,
            info.offset + info.length
        );
        out.seek(SeekFrom::Start(info.offset))
            .with_context(|| format!("Seeking to offset {}", info.offset))?;
        if info.length > 0 {
            callback(&mut out, &info.name)
                .with_context(|| format!("Failed to write file {}", info.name))?;
            let cur = out.stream_position().context("Getting current position")?;
            if cur != info.offset + info.length {
                return Err(nod::Error::Other(format!(
                    "Wrote {} bytes, expected {}",
                    cur - info.offset,
                    info.length
                )));
            }
        }
        last_end = info.offset + info.length;
    }
    if let Some(junk_id) = junk_id {
        let aligned_end = gcm_align(last_end);
        if aligned_end < MINI_DVD_SIZE && aligned_end >= fst_end {
            debug!("Writing junk data at {:X} -> {:X}", aligned_end, MINI_DVD_SIZE);
            write_junk_data(
                &mut lfg,
                &mut out,
                junk_id,
                header.disc_num,
                aligned_end,
                MINI_DVD_SIZE,
            )?;
            last_end = MINI_DVD_SIZE;
        }
    }
    out.write_zeroes(MINI_DVD_SIZE - last_end).context("Writing end of file")?;
    out.flush().context("Flushing output")?;
    Ok(out.finish())
}

fn write_junk_data<W>(
    lfg: &mut LaggedFibonacci,
    out: &mut W,
    junk_id: [u8; 4],
    disc_num: u8,
    pos: u64,
    end: u64,
) -> nod::Result<()>
where
    W: Write + Seek + ?Sized,
{
    out.seek(SeekFrom::Start(pos)).with_context(|| format!("Seeking to offset {}", pos))?;
    lfg.write_sector_chunked(out, end - pos, junk_id, disc_num, pos)
        .with_context(|| format!("Failed to write junk data at offset {}", pos))?;
    Ok(())
}

pub fn run_test(args: TestArgs) -> nod::Result<()> {
    let mut failed = vec![];
    for input in args.inputs {
        match in_memory_test(&input, args.output.as_deref(), args.test_output.as_deref()) {
            Ok(()) => {}
            Err(e) => {
                error!("Failed to generate disc image: {:?}", e);
                failed.push((input, e));
            }
        }
    }
    if !failed.is_empty() {
        error!("Failed to generate disc images:");
        for (input, e) in failed {
            error!("  {}: {:?}", input.display(), e);
        }
        std::process::exit(1);
    }
    Ok(())
}

/// Some games (mainly beta and sample discs) have junk data that doesn't match the game ID. This
/// function returns the correct game ID to use, if an override is needed.
fn get_override_junk_id(header: &DiscHeader) -> Option<[u8; 4]> {
    match &header.game_id {
        // Dairantou Smash Brothers DX (Japan) (Taikenban)
        b"DALJ01" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"DPIJ"),
        // 2002 FIFA World Cup (Japan) (Jitsuen-you Sample)
        b"DFIJ13" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GFIJ"),
        // Disney's Magical Park (Japan) (Jitsuen-you Sample)
        b"DMTJ18" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GMTJ"),
        // Star Wars - Rogue Squadron II (Japan) (Jitsuen-you Sample)
        b"DSWJ13" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GSWJ"),
        // Homeland (Japan) (Rev 1) [T-En by DOL-Translations v20230606] [i]
        b"GHEE91" if header.disc_num == 0 && header.disc_version == 1 => Some(*b"GHEJ"),
        // Kururin Squash! (Japan) [T-En by DOL-Translations v2.0.0]
        b"GKQE01" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GKQJ"),
        // Lupin III - Lost Treasure Under the Sea (Japan) (Disc 1) [T-En by DOL-Translations v0.5.0] [i] [n]
        b"GL3EE8" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GL3J"),
        // Lupin III - Lost Treasure Under the Sea (Japan) (Disc 2) [T-En by DOL-Translations v0.5.0] [i] [n]
        b"GL3EE8" if header.disc_num == 1 && header.disc_version == 0 => Some(*b"GL3J"),
        // Taxi 3 - The Game (France) [T-En by DOL-Translations v20230801] [n]
        b"GXQP41" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GXQF"),
        // Donkey Konga 3 - Tabehoudai! Haru Mogitate 50-kyoku (Japan) [T-En by DOL-Translations v0.1.1] [i]
        b"GY3E01" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GY3J"),
        // Need for Speed - Underground (Europe) (Alt)
        b"PZHP69" if header.disc_num == 0 && header.disc_version == 0 => Some(*b"GNDP"),
        _ => None,
    }
}

fn get_junk_id(header: &DiscHeader) -> Option<[u8; 4]> {
    Some(match get_override_junk_id(header) {
        Some(id) => {
            info!("Using override junk ID: {:X?}", from_utf8(&id).unwrap());
            id
        }
        None => *array_ref!(header.game_id, 0, 4),
    })
}

fn sort_files(files: &mut [FileWriteInfo]) -> nod::Result<()> {
    files.sort_unstable_by_key(|info| (info.offset, info.length));
    for i in 1..files.len() {
        let prev = &files[i - 1];
        let cur = &files[i];
        if cur.offset < prev.offset + prev.length {
            return Err(nod::Error::Other(format!(
                "File {} ({:#X}-{:#X}) overlaps with {} ({:#X}-{:#X})",
                cur.name,
                cur.offset,
                cur.offset + cur.length,
                prev.name,
                prev.offset,
                prev.offset + prev.length
            )));
        }
    }
    Ok(())
}

fn in_memory_test(
    path: &Path,
    output: Option<&Path>,
    test_output: Option<&Path>,
) -> nod::Result<()> {
    let start = Instant::now();
    info!("Opening disc image '{}'", path.display());
    let disc = DiscReader::new(path, &DiscOptions::default())?;
    info!(
        "Opened disc image '{}' (Disc {}, Revision {})",
        disc.header().game_title_str(),
        disc.header().disc_num + 1,
        disc.header().disc_version
    );
    let Some(orig_crc32) = disc.meta().crc32 else {
        return Err(nod::Error::Other("CRC32 not found in disc metadata".to_string()));
    };
    let mut partition =
        disc.open_partition_kind(PartitionKind::Data, &PartitionOptions::default())?;
    let meta = partition.meta()?;

    // Build metadata
    let mut file_infos = Vec::new();
    let header = meta.disc_header();
    let junk_id = get_junk_id(header);
    let boot_header = meta.boot_header();
    let fst = meta.fst()?;

    file_infos.push(FileWriteInfo {
        name: "sys/boot.bin".to_string(),
        offset: 0,
        length: BOOT_SIZE as u64,
    });
    file_infos.push(FileWriteInfo {
        name: "sys/bi2.bin".to_string(),
        offset: BOOT_SIZE as u64,
        length: BI2_SIZE as u64,
    });
    file_infos.push(FileWriteInfo {
        name: "sys/apploader.img".to_string(),
        offset: BOOT_SIZE as u64 + BI2_SIZE as u64,
        length: meta.raw_apploader.len() as u64,
    });
    let fst_offset = boot_header.fst_offset(false);
    let dol_offset = boot_header.dol_offset(false);
    if dol_offset < fst_offset {
        file_infos.push(FileWriteInfo {
            name: "sys/main.dol".to_string(),
            offset: dol_offset,
            length: meta.raw_dol.len() as u64,
        });
    } else {
        let mut found = false;
        for (_, node, name) in fst.iter() {
            if !node.is_file() {
                continue;
            }
            let offset = node.offset(false);
            if offset == dol_offset {
                info!("Using DOL from FST: {}", name);
                found = true;
            }
        }
        if !found {
            return Err(nod::Error::Other("DOL not found in FST".to_string()));
        }
    }
    let fst_size = boot_header.fst_size(false);
    file_infos.push(FileWriteInfo {
        name: "sys/fst.bin".to_string(),
        offset: fst_offset,
        length: fst_size,
    });

    // Collect files
    let mut builder = GCPartitionBuilder::new(false, PartitionOverrides::default());
    for (idx, node, path) in fst.iter() {
        let offset = node.offset(false);
        let length = node.length() as u64;
        if node.is_dir() {
            if length as usize == idx + 1 {
                println!("Empty directory: {}", path);
            }
            continue;
        }

        if let Some(junk_id) = junk_id {
            // Some games have junk data in place of files that were removed from the disc layout.
            // This is a naive check to skip these files in our disc layout so that the junk data
            // alignment is correct. This misses some cases where the junk data starts in the middle
            // of a file, but handling those cases would require a more complex solution.
            if length > 4
                && check_junk_data(partition.as_mut(), offset, length, junk_id, header.disc_num)?
            {
                warn!("Skipping junk data file: {} (size {})", path, length);
                builder.add_junk_file(path);
                continue;
            }
        }

        builder.add_file(FileInfo {
            name: path,
            size: length,
            offset: Some(offset),
            alignment: None,
        })?;
    }

    // Write files
    info!("Writing disc image with {} files", file_infos.len());
    for file in &file_infos {
        builder.add_file(FileInfo {
            name: file.name.clone(),
            size: file.length,
            offset: Some(file.offset),
            alignment: None,
        })?;
    }
    let writer = builder.build(|out: &mut dyn Write, name: &str| match name {
        "sys/boot.bin" => out.write_all(meta.raw_boot.as_ref()),
        "sys/bi2.bin" => out.write_all(meta.raw_bi2.as_ref()),
        "sys/fst.bin" => out.write_all(meta.raw_fst.as_ref()),
        "sys/apploader.img" => out.write_all(meta.raw_apploader.as_ref()),
        "sys/main.dol" => out.write_all(meta.raw_dol.as_ref()),
        path => {
            let Some((_, node)) = fst.find(path) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("File not found: {}", path),
                ));
            };
            let mut file = partition.open_file(node)?;
            buf_copy(&mut file, out)?;
            Ok(())
        }
    })?;
    let disc_stream = writer.into_cloneable_stream(PartitionFileReader { partition, meta })?;
    let disc_reader = DiscReader::new_stream(disc_stream, &DiscOptions::default())?;
    let disc_writer = DiscWriter::new(disc_reader, &FormatOptions::default())?;
    let process_options = ProcessOptions { digest_crc32: true, ..Default::default() };
    let finalization = if let Some(output) = output {
        let mut out = File::create(output)
            .with_context(|| format!("Failed to create {}", output.display()))?;
        let finalization =
            disc_writer.process(|data, _, _| out.write_all(data.as_ref()), &process_options)?;
        out.flush().context("Failed to flush output file")?;
        finalization
    } else {
        disc_writer.process(|_, _, _| Ok(()), &process_options)?
    };
    let crc = finalization.crc32.unwrap();
    info!("Generated disc image in {:?} (CRC32: {:08X})", start.elapsed(), crc);
    if crc != orig_crc32 {
        if let Some(test_output) = test_output {
            let open_options = DiscOptions {
                partition_encryption: PartitionEncryption::Original,
                preloader_threads: 4,
            };
            convert_and_verify(
                path,
                Some(test_output),
                false,
                &open_options,
                &FormatOptions::default(),
            )?;
        }
        return Err(nod::Error::Other(format!(
            "CRC32 mismatch: {:08X} != {:08X}",
            crc, orig_crc32
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct PartitionFileReader {
    partition: Box<dyn PartitionReader>,
    meta: PartitionMeta,
}

impl FileCallback for PartitionFileReader {
    fn read_file(&mut self, out: &mut [u8], name: &str, offset: u64) -> io::Result<()> {
        let data: &[u8] = match name {
            "sys/boot.bin" => self.meta.raw_boot.as_ref(),
            "sys/bi2.bin" => self.meta.raw_bi2.as_ref(),
            "sys/fst.bin" => self.meta.raw_fst.as_ref(),
            "sys/apploader.img" => self.meta.raw_apploader.as_ref(),
            "sys/main.dol" => self.meta.raw_dol.as_ref(),
            path => {
                let fst = self.meta.fst().map_err(io::Error::other)?;
                let Some((_, node)) = fst.find(path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("File not found: {}", path),
                    ));
                };
                let mut file = self.partition.open_file(node)?;
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(out)?;
                return Ok(());
            }
        };
        let offset = offset as usize;
        let len = out.len().min(data.len() - offset);
        out[..len].copy_from_slice(&data[offset..offset + len]);
        Ok(())
    }
}

/// Some disc files still exist in the FST, but were removed from the disc layout. These files had
/// junk data written in their place, since the disc creator did not know about them. To match the
/// original disc, we need to check for these files and remove them from our disc layout as well.
/// This ensures that the junk data alignment is correct.
fn check_junk_data(
    partition: &mut dyn PartitionReader,
    offset: u64,
    len: u64,
    junk_id: [u8; 4],
    disc_num: u8,
) -> nod::Result<bool> {
    if len == 0 {
        return Ok(false);
    }

    partition
        .seek(SeekFrom::Start(offset))
        .with_context(|| format!("Seeking to offset {}", offset))?;
    let mut lfg = LaggedFibonacci::default();
    let mut pos = offset;
    let mut remaining = len;
    while remaining > 0 {
        let file_buf = partition
            .fill_buf()
            .with_context(|| format!("Failed to read disc file at offset {}", offset))?;
        let read_len = (file_buf.len() as u64).min(remaining) as usize;
        if lfg.check_sector_chunked(&file_buf[..read_len], junk_id, disc_num, pos) != read_len {
            return Ok(false);
        }

        pos += read_len as u64;
        remaining -= read_len as u64;
        partition.consume(read_len);
    }
    Ok(true)
}

pub struct HashStream<W> {
    inner: W,
    hasher: crc32fast::Hasher,
    position: u64,
}

impl<W> HashStream<W> {
    pub fn new(inner: W) -> Self { Self { inner, hasher: Default::default(), position: 0 } }

    pub fn finish(self) -> u32 { self.hasher.finalize() }
}

impl<W> HashStream<W>
where W: Write
{
    pub fn write_zeroes(&mut self, mut len: u64) -> io::Result<()> {
        while len > 0 {
            let write_len = len.min(SECTOR_SIZE as u64) as usize;
            self.write_all(&ZERO_SECTOR[..write_len])?;
            len -= write_len as u64;
        }
        Ok(())
    }
}

impl<W> Write for HashStream<W>
where W: Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.position += buf.len() as u64;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

static ZERO_SECTOR: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

impl<W> Seek for HashStream<W>
where W: Write
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::Current(v) => self.position.saturating_add_signed(v),
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "HashStream: SeekFrom::End is not supported".to_string(),
                ));
            }
        };
        if new_position < self.position {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HashStream: Cannot seek backwards".to_string(),
            ));
        }
        self.write_zeroes(new_position - self.position)?;
        Ok(new_position)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.position) }
}
