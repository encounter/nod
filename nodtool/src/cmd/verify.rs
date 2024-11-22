use std::path::PathBuf;

use argp::FromArgs;
use nod::{
    read::{DiscOptions, PartitionEncryption},
    write::FormatOptions,
};

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
    #[argp(switch)]
    /// decrypt Wii partition data
    decrypt: bool,
    #[argp(switch)]
    /// encrypt Wii partition data
    encrypt: bool,
}

pub fn run(args: Args) -> nod::Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    let cpus = num_cpus::get();
    let options = DiscOptions {
        partition_encryption: match (args.decrypt, args.encrypt) {
            (true, false) => PartitionEncryption::ForceDecrypted,
            (false, true) => PartitionEncryption::ForceEncrypted,
            (false, false) => PartitionEncryption::Original,
            (true, true) => {
                return Err(nod::Error::Other("Both --decrypt and --encrypt specified".to_string()))
            }
        },
        preloader_threads: 4.min(cpus),
    };
    let format_options = FormatOptions::default();
    for file in &args.file {
        convert_and_verify(file, None, args.md5, &options, &format_options)?;
        println!();
    }
    Ok(())
}
