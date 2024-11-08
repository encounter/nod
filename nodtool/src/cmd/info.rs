use std::path::{Path, PathBuf};

use argp::FromArgs;
use nod::{Disc, SECTOR_SIZE};
use size::Size;

use crate::util::{display, shared::print_header};

#[derive(FromArgs, Debug)]
/// Displays information about disc images.
#[argp(subcommand, name = "info")]
pub struct Args {
    #[argp(positional)]
    /// Path to disc image(s)
    file: Vec<PathBuf>,
}

pub fn run(args: Args) -> nod::Result<()> {
    for file in &args.file {
        info_file(file)?;
    }
    Ok(())
}

fn info_file(path: &Path) -> nod::Result<()> {
    log::info!("Loading {}", display(path));
    let disc = Disc::new(path)?;
    let header = disc.header();
    let meta = disc.meta();
    print_header(header, &meta);

    if header.is_wii() {
        for (idx, info) in disc.partitions().iter().enumerate() {
            let mut partition = disc.open_partition(idx)?;
            let meta = partition.meta()?;

            println!();
            println!("Partition {}", idx);
            println!("\tType: {}", info.kind);
            let offset = info.start_sector as u64 * SECTOR_SIZE as u64;
            println!("\tStart sector: {} (offset {:#X})", info.start_sector, offset);
            let data_size =
                (info.data_end_sector - info.data_start_sector) as u64 * SECTOR_SIZE as u64;
            if info.has_encryption {
                println!(
                    "\tEncrypted data offset / size: {:#X} / {:#X} ({})",
                    info.data_start_sector as u64 * SECTOR_SIZE as u64,
                    data_size,
                    Size::from_bytes(data_size)
                );
            } else {
                println!(
                    "\tDecrypted data offset / size: {:#X} / {:#X} ({})",
                    offset,
                    data_size,
                    Size::from_bytes(data_size)
                );
            }
            println!(
                "\tTMD offset / size: {:#X} / {:#X}",
                offset + info.header.tmd_off(),
                info.header.tmd_size()
            );
            if let Some(content_metadata) = meta.content_metadata() {
                for content in content_metadata {
                    println!(
                        "\t-> Content {:08X} size: {:#X} ({})",
                        content.content_index.get(),
                        content.size.get(),
                        Size::from_bytes(content.size.get()),
                    );
                }
            }
            println!(
                "\tCert chain offset / size: {:#X} / {:#X}",
                offset + info.header.cert_chain_off(),
                info.header.cert_chain_size()
            );
            println!(
                "\tH3 table offset / size: {:#X} / {:#X}",
                offset + info.header.h3_table_off(),
                info.header.h3_table_size()
            );

            let tmd = meta.tmd_header();
            let title_id_str = if let Some(tmd) = tmd {
                hex::encode_upper(tmd.title_id)
            } else {
                "N/A".to_string()
            };
            println!("\tTitle: {}", info.disc_header.game_title_str());
            println!("\tGame ID: {} ({})", info.disc_header.game_id_str(), title_id_str);
            println!(
                "\tDisc {}, Revision {}",
                info.disc_header.disc_num + 1,
                info.disc_header.disc_version
            );
        }
    } else if header.is_gamecube() {
        // TODO
    } else {
        println!("Invalid GC/Wii magic: {:#x?}/{:#x?}", header.gcn_magic, header.wii_magic);
    }
    println!();
    Ok(())
}
