use std::path::PathBuf;

use argp::FromArgs;
use nod::{OpenOptions, PartitionEncryptionMode};

use crate::util::{redump, shared::convert_and_verify};

#[derive(FromArgs, Debug)]
/// Verifies disc images.
#[argp(subcommand, name = "verify")]
pub struct Args {
    #[argp(positional)]
    /// path to disc image(s)
    file: Vec<PathBuf>,
    #[argp(switch)]
    /// enable MD5 hashing (slower)
    md5: bool,
    #[argp(option, short = 'd')]
    /// path to DAT file(s) for verification (optional)
    dat: Vec<PathBuf>,
}

pub fn run(args: Args) -> nod::Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    let options = OpenOptions { partition_encryption: PartitionEncryptionMode::Original };
    for file in &args.file {
        convert_and_verify(file, None, args.md5, &options)?;
        println!();
    }
    Ok(())
}
