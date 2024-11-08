use std::path::PathBuf;

use argp::FromArgs;
use nod::OpenOptions;

use crate::util::{redump, shared::convert_and_verify};

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
}

pub fn run(args: Args) -> nod::Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    let options = OpenOptions {
        partition_encryption: match (args.decrypt, args.encrypt) {
            (true, false) => nod::PartitionEncryptionMode::ForceDecrypted,
            (false, true) => nod::PartitionEncryptionMode::ForceEncrypted,
            (false, false) => nod::PartitionEncryptionMode::Original,
            (true, true) => {
                return Err(nod::Error::Other("Both --decrypt and --encrypt specified".to_string()))
            }
        },
    };
    convert_and_verify(&args.file, Some(&args.out), args.md5, &options)
}
