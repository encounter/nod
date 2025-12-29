use std::{
    fs,
    fs::File,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use argp::FromArgs;
use nod::{
    ResultContext,
    common::PartitionKind,
    disc::fst::{Fst, Node},
    read::{DiscOptions, DiscReader, PartitionMeta, PartitionOptions, PartitionReader},
};
use size::{Base, Size};
use zerocopy::IntoBytes;

use crate::util::{has_extension, path_display};

#[derive(FromArgs, Debug)]
/// Extracts a disc image.
#[argp(subcommand, name = "extract")]
pub struct Args {
    #[argp(positional)]
    /// Path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// Output directory (optional)
    out: Option<PathBuf>,
    #[argp(switch, short = 'q')]
    /// Quiet output
    quiet: bool,
    #[argp(switch, short = 'h')]
    /// Validate data hashes (Wii only)
    validate: bool,
    #[argp(option, short = 'p')]
    /// Partition to extract (default: data)
    /// Options: all, data, update, channel, or a partition index
    partition: Option<String>,
}

pub fn run(args: Args) -> nod::Result<()> {
    let output_dir: PathBuf;
    if let Some(dir) = args.out {
        output_dir = dir;
    } else if has_extension(&args.file, "nfs") {
        // Special logic to extract from content/hif_*.nfs to extracted/..
        if let Some(parent) = args.file.parent() {
            output_dir = parent.with_file_name("extracted");
        } else {
            output_dir = args.file.with_extension("");
        }
    } else {
        output_dir = args.file.with_extension("");
    }
    let disc = DiscReader::new(&args.file, &DiscOptions {
        #[cfg(feature = "threading")]
        preloader_threads: 4,
        ..Default::default()
    })?;
    let header = disc.header();
    let is_wii = header.is_wii();
    let options = PartitionOptions { validate_hashes: args.validate };
    if let Some(partition) = args.partition {
        if partition.eq_ignore_ascii_case("all") {
            for info in disc.partitions() {
                let mut out_dir = output_dir.clone();
                out_dir.push(info.kind.dir_name().as_ref());
                let mut partition = disc.open_partition(info.index, &options)?;
                extract_partition(&disc, partition.as_mut(), &out_dir, is_wii, args.quiet)?;
            }
        } else if partition.eq_ignore_ascii_case("data") {
            let mut partition = disc.open_partition_kind(PartitionKind::Data, &options)?;
            extract_partition(&disc, partition.as_mut(), &output_dir, is_wii, args.quiet)?;
        } else if partition.eq_ignore_ascii_case("update") {
            let mut partition = disc.open_partition_kind(PartitionKind::Update, &options)?;
            extract_partition(&disc, partition.as_mut(), &output_dir, is_wii, args.quiet)?;
        } else if partition.eq_ignore_ascii_case("channel") {
            let mut partition = disc.open_partition_kind(PartitionKind::Channel, &options)?;
            extract_partition(&disc, partition.as_mut(), &output_dir, is_wii, args.quiet)?;
        } else {
            let idx = partition.parse::<usize>().map_err(|_| "Invalid partition index")?;
            let mut partition = disc.open_partition(idx, &options)?;
            extract_partition(&disc, partition.as_mut(), &output_dir, is_wii, args.quiet)?;
        }
    } else {
        let mut partition = disc.open_partition_kind(PartitionKind::Data, &options)?;
        extract_partition(&disc, partition.as_mut(), &output_dir, is_wii, args.quiet)?;
    }
    Ok(())
}

fn extract_partition(
    disc: &DiscReader,
    partition: &mut dyn PartitionReader,
    out_dir: &Path,
    is_wii: bool,
    quiet: bool,
) -> nod::Result<()> {
    let meta = partition.meta()?;
    extract_sys_files(disc, &meta, out_dir, quiet)?;

    // Extract FST
    let files_dir = out_dir.join("files");
    fs::create_dir_all(&files_dir)
        .with_context(|| format!("Creating directory {}", path_display(&files_dir)))?;

    let fst = Fst::new(&meta.raw_fst)?;
    for (_, node, path) in fst.iter() {
        if node.is_dir() {
            fs::create_dir_all(files_dir.join(&path))
                .with_context(|| format!("Creating directory {}", path))?;
        } else {
            extract_node(node, partition, &files_dir, &path, is_wii, quiet)?;
        }
    }
    Ok(())
}

fn extract_sys_files(
    disc: &DiscReader,
    data: &PartitionMeta,
    out_dir: &Path,
    quiet: bool,
) -> nod::Result<()> {
    let sys_dir = out_dir.join("sys");
    fs::create_dir_all(&sys_dir)
        .with_context(|| format!("Creating directory {}", path_display(&sys_dir)))?;
    extract_file(data.raw_boot.as_ref(), &sys_dir.join("boot.bin"), quiet)?;
    extract_file(data.raw_bi2.as_ref(), &sys_dir.join("bi2.bin"), quiet)?;
    extract_file(data.raw_apploader.as_ref(), &sys_dir.join("apploader.img"), quiet)?;
    extract_file(data.raw_fst.as_ref(), &sys_dir.join("fst.bin"), quiet)?;
    extract_file(data.raw_dol.as_ref(), &sys_dir.join("main.dol"), quiet)?;

    // Wii files
    let disc_header = disc.header();
    if disc_header.is_wii() {
        let disc_dir = out_dir.join("disc");
        fs::create_dir_all(&disc_dir)
            .with_context(|| format!("Creating directory {}", path_display(&disc_dir)))?;
        extract_file(&disc_header.as_bytes()[..0x100], &disc_dir.join("header.bin"), quiet)?;
        if let Some(region) = disc.region() {
            extract_file(region, &disc_dir.join("region.bin"), quiet)?;
        }
        if let Some(ticket) = data.raw_ticket.as_deref() {
            extract_file(ticket, &out_dir.join("ticket.bin"), quiet)?;
        }
        if let Some(tmd) = data.raw_tmd.as_deref() {
            extract_file(tmd, &out_dir.join("tmd.bin"), quiet)?;
        }
        if let Some(cert_chain) = data.raw_cert_chain.as_deref() {
            extract_file(cert_chain, &out_dir.join("cert.bin"), quiet)?;
        }
        if let Some(h3_table) = data.raw_h3_table.as_deref() {
            extract_file(h3_table, &out_dir.join("h3.bin"), quiet)?;
        }
    }
    Ok(())
}

fn extract_file(bytes: &[u8], out_path: &Path, quiet: bool) -> nod::Result<()> {
    if !quiet {
        println!(
            "Extracting {} (size: {})",
            path_display(out_path),
            Size::from_bytes(bytes.len()).format().with_base(Base::Base10)
        );
    }
    fs::write(out_path, bytes)
        .with_context(|| format!("Writing file {}", path_display(out_path)))?;
    Ok(())
}

fn extract_node(
    node: Node,
    partition: &mut dyn PartitionReader,
    base_path: &Path,
    name: &str,
    is_wii: bool,
    quiet: bool,
) -> nod::Result<()> {
    let file_path = base_path.join(name);
    if !quiet {
        println!(
            "Extracting {} (size: {})",
            path_display(&file_path),
            Size::from_bytes(node.length()).format().with_base(Base::Base10)
        );
    }
    let mut file = File::create(&file_path)
        .with_context(|| format!("Creating file {}", path_display(&file_path)))?;
    let mut r = partition.open_file(node).with_context(|| {
        format!(
            "Opening file {} on disc for reading (offset {}, size {})",
            name,
            node.offset(is_wii),
            node.length()
        )
    })?;
    loop {
        let buf = r
            .fill_buf()
            .with_context(|| format!("Extracting file {}", path_display(&file_path)))?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        file.write_all(buf)
            .with_context(|| format!("Writing file {}", path_display(&file_path)))?;
        r.consume(len);
    }
    file.flush().with_context(|| format!("Flushing file {}", path_display(&file_path)))?;
    Ok(())
}
