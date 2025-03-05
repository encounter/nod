use std::{
    io,
    io::{BufRead, Read},
};

use bytes::{Bytes, BytesMut};
use dyn_clone::DynClone;
use rayon::prelude::*;

use crate::{
    Error, Result, ResultContext,
    common::PartitionInfo,
    disc::{
        SECTOR_SIZE,
        reader::DiscReader,
        wii::{HASHES_SIZE, SECTOR_DATA_SIZE},
    },
    util::{aes::decrypt_sector_b2b, array_ref, array_ref_mut, lfg::LaggedFibonacci},
    write::{DiscFinalization, DiscWriterWeight, ProcessOptions},
};

/// A callback for writing disc data.
///
/// The callback should write all data to the output stream before returning, or return an error if
/// writing fails. The second and third arguments are the current bytes processed and the total
/// bytes to process, respectively. For most formats, this has no relation to the written disc size,
/// but can be used to display progress.
pub type DataCallback<'a> = dyn FnMut(Bytes, u64, u64) -> io::Result<()> + Send + 'a;

/// A trait for writing disc images.
pub trait DiscWriter: DynClone {
    /// Processes the disc writer to completion.
    ///
    /// The data callback will be called, in order, for each block of data to write to the output
    /// file. The callback should write all data before returning, or return an error if writing
    /// fails.
    fn process(
        &self,
        data_callback: &mut DataCallback,
        options: &ProcessOptions,
    ) -> Result<DiscFinalization>;

    /// Returns the progress upper bound for the disc writer.
    ///
    /// For most formats, this has no relation to the written disc size, but can be used to display
    /// progress.
    fn progress_bound(&self) -> u64;

    /// Returns the weight of the disc writer.
    ///
    /// This can help determine the number of threads to dedicate for output processing, and may
    /// differ based on the format's configuration, such as whether compression is enabled.
    fn weight(&self) -> DiscWriterWeight;
}

dyn_clone::clone_trait_object!(DiscWriter);

#[derive(Default)]
pub struct BlockResult<T> {
    /// Input block index
    pub block_idx: u32,
    /// Input disc data (before processing)
    pub disc_data: Bytes,
    /// Output block data (after processing). If None, the disc data is used.
    pub block_data: Bytes,
    /// Output metadata
    pub meta: T,
}

pub trait BlockProcessor: Clone + Send + Sync {
    type BlockMeta;

    fn process_block(&mut self, block_idx: u32) -> io::Result<BlockResult<Self::BlockMeta>>;
}

pub fn read_block(reader: &mut DiscReader, block_size: usize) -> io::Result<(Bytes, Bytes)> {
    let initial_block = reader.fill_buf_internal()?;
    if initial_block.len() >= block_size {
        // Happy path: we have a full block that we can cheaply slice
        let data = initial_block.slice(0..block_size);
        reader.consume(block_size);
        return Ok((data.clone(), data));
    } else if initial_block.is_empty() {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    reader.consume(initial_block.len());

    // Combine smaller blocks into a new buffer
    let mut buf = BytesMut::zeroed(block_size);
    let mut len = initial_block.len();
    buf[..len].copy_from_slice(initial_block.as_ref());
    drop(initial_block);
    while len < block_size {
        let read = reader.read(&mut buf[len..])?;
        if read == 0 {
            break;
        }
        len += read;
    }
    // The block data is full size, padded with zeroes
    let block_data = buf.freeze();
    // The disc data is the actual data read, without padding
    let disc_data = block_data.slice(0..len);
    Ok((block_data, disc_data))
}

/// Process blocks in parallel, ensuring that they are written in order.
pub(crate) fn par_process<P, T>(
    create_processor: impl Fn() -> P + Sync,
    block_count: u32,
    num_threads: usize,
    mut callback: impl FnMut(BlockResult<T>) -> Result<()> + Send,
) -> Result<()>
where
    T: Send,
    P: BlockProcessor<BlockMeta = T>,
{
    if num_threads == 0 {
        // Fall back to single-threaded processing
        let mut processor = create_processor();
        for block_idx in 0..block_count {
            let block = processor
                .process_block(block_idx)
                .with_context(|| format!("Failed to process block {block_idx}"))?;
            callback(block)?;
        }
        return Ok(());
    }

    let (block_tx, block_rx) = crossbeam_channel::bounded(block_count as usize);
    for block_idx in 0..block_count {
        block_tx.send(block_idx).unwrap();
    }
    drop(block_tx); // Disconnect channel

    let (result_tx, result_rx) = crossbeam_channel::bounded(0);
    let mut process_error = None;
    let mut write_error = None;
    rayon::join(
        || {
            if let Err(e) = (0..num_threads).into_par_iter().try_for_each_init(
                || (block_rx.clone(), result_tx.clone(), create_processor()),
                |(receiver, block_tx, processor), _| {
                    while let Ok(block_idx) = receiver.recv() {
                        let block = processor
                            .process_block(block_idx)
                            .with_context(|| format!("Failed to process block {block_idx}"))?;
                        if block_tx.send(block).is_err() {
                            break;
                        }
                    }
                    Ok::<_, Error>(())
                },
            ) {
                process_error = Some(e);
            }
            drop(result_tx); // Disconnect channel
        },
        || {
            let mut current_block = 0;
            let mut out_of_order = Vec::<BlockResult<T>>::new();
            'outer: while let Ok(result) = result_rx.recv() {
                if result.block_idx == current_block {
                    if let Err(e) = callback(result) {
                        write_error = Some(e);
                        break;
                    }
                    current_block += 1;
                    // Check if any out of order blocks can be written
                    while out_of_order.first().is_some_and(|r| r.block_idx == current_block) {
                        let result = out_of_order.remove(0);
                        if let Err(e) = callback(result) {
                            write_error = Some(e);
                            break 'outer;
                        }
                        current_block += 1;
                    }
                } else {
                    out_of_order.push(result);
                    out_of_order.sort_unstable_by_key(|r| r.block_idx);
                }
            }
        },
    );
    if let Some(e) = process_error {
        return Err(e);
    }
    if let Some(e) = write_error {
        return Err(e);
    }

    Ok(())
}

/// The determined block type.
pub enum CheckBlockResult {
    Normal,
    Zeroed,
    Junk,
}

/// Check if a block is zeroed or junk data.
pub(crate) fn check_block(
    buf: &[u8],
    decrypted_block: &mut [u8],
    input_position: u64,
    partition_info: &[PartitionInfo],
    lfg: &mut LaggedFibonacci,
    disc_id: [u8; 4],
    disc_num: u8,
) -> io::Result<CheckBlockResult> {
    let start_sector = (input_position / SECTOR_SIZE as u64) as u32;
    let end_sector = ((input_position + buf.len() as u64) / SECTOR_SIZE as u64) as u32;
    if let Some(partition) = partition_info.iter().find(|p| {
        p.has_hashes && start_sector >= p.data_start_sector && end_sector < p.data_end_sector
    }) {
        if input_position % SECTOR_SIZE as u64 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Partition block not aligned to sector boundary",
            ));
        }
        if buf.len() % SECTOR_SIZE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Partition block not a multiple of sector size",
            ));
        }
        let block = if partition.has_encryption {
            if decrypted_block.len() < buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Decrypted block buffer too small",
                ));
            }
            for i in 0..buf.len() / SECTOR_SIZE {
                decrypt_sector_b2b(
                    array_ref![buf, SECTOR_SIZE * i, SECTOR_SIZE],
                    array_ref_mut![decrypted_block, SECTOR_SIZE * i, SECTOR_SIZE],
                    &partition.key,
                );
            }
            &decrypted_block[..buf.len()]
        } else {
            buf
        };
        if sector_data_iter(block).all(|sector_data| sector_data.iter().all(|&b| b == 0)) {
            return Ok(CheckBlockResult::Zeroed);
        }
        let partition_start = partition.data_start_sector as u64 * SECTOR_SIZE as u64;
        let partition_offset =
            ((input_position - partition_start) / SECTOR_SIZE as u64) * SECTOR_DATA_SIZE as u64;
        if sector_data_iter(block).enumerate().all(|(i, sector_data)| {
            let sector_offset = partition_offset + i as u64 * SECTOR_DATA_SIZE as u64;
            lfg.check_sector_chunked(sector_data, disc_id, disc_num, sector_offset)
                == sector_data.len()
        }) {
            return Ok(CheckBlockResult::Junk);
        }
    } else {
        if buf.iter().all(|&b| b == 0) {
            return Ok(CheckBlockResult::Zeroed);
        }
        if lfg.check_sector_chunked(buf, disc_id, disc_num, input_position) == buf.len() {
            return Ok(CheckBlockResult::Junk);
        }
    }
    Ok(CheckBlockResult::Normal)
}

#[inline]
fn sector_data_iter(buf: &[u8]) -> impl Iterator<Item = &[u8; SECTOR_DATA_SIZE]> {
    buf.chunks_exact(SECTOR_SIZE).map(|chunk| (&chunk[HASHES_SIZE..]).try_into().unwrap())
}
