use std::{ffi::OsStr, path::PathBuf};

use argp::FromArgs;
use nod::{
    common::Format,
    read::{DiscOptions, PartitionEncryption},
    write::FormatOptions,
};

use crate::util::{path_display, redump, shared::convert_and_verify};

#[derive(FromArgs, Debug)]
/// Converts a disc image to ISO.
#[argp(subcommand, name = "convert")]
pub struct Args {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// output ISO file
    out: PathBuf,
    #[argp(switch)]
    /// enable MD5 hashing (slower)
    md5: bool,
    #[argp(option, short = 'd')]
    /// path to DAT file(s) for verification (optional)
    dat: Vec<PathBuf>,
    #[argp(switch)]
    /// decrypt Wii partition data
    decrypt: bool,
    #[argp(switch)]
    /// encrypt Wii partition data
    encrypt: bool,
    #[argp(option, short = 'c')]
    /// compression format and level (e.g. "zstd:19")
    compress: Option<String>,
}

pub fn run(args: Args) -> nod::Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    let options = DiscOptions {
        partition_encryption: match (args.decrypt, args.encrypt) {
            (true, false) => PartitionEncryption::ForceDecrypted,
            (false, true) => PartitionEncryption::ForceEncrypted,
            (false, false) => PartitionEncryption::Original,
            (true, true) => {
                return Err(nod::Error::Other(
                    "Both --decrypt and --encrypt specified".to_string(),
                ));
            }
        },
        #[cfg(feature = "threading")]
        preloader_threads: 4,
    };
    let format = match args.out.extension() {
        Some(ext)
            if ext.eq_ignore_ascii_case(OsStr::new("iso"))
                || ext.eq_ignore_ascii_case(OsStr::new("gcm")) =>
        {
            Format::Iso
        }
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("ciso")) => Format::Ciso,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("gcz")) => Format::Gcz,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("nfs")) => Format::Nfs,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("rvz")) => Format::Rvz,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("wbfs")) => Format::Wbfs,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("wia")) => Format::Wia,
        Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("tgc")) => Format::Tgc,
        Some(_) => {
            return Err(nod::Error::Other(format!(
                "Unknown file extension: {}",
                path_display(&args.out)
            )));
        }
        None => Format::Iso,
    };
    let mut compression = if let Some(compress) = args.compress {
        compress.parse()?
    } else {
        format.default_compression()
    };
    compression.validate_level()?;
    let format_options =
        FormatOptions { format, compression, block_size: format.default_block_size() };
    convert_and_verify(&args.file, Some(&args.out), args.md5, &options, &format_options)
}
