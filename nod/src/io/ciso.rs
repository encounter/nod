use std::{
    io,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    sync::Arc,
};

use bytes::{BufMut, Bytes, BytesMut};
use zerocopy::{little_endian::*, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::{
    common::{Compression, Format, MagicBytes},
    disc::{
        reader::DiscReader,
        writer::{
            check_block, par_process, read_block, BlockProcessor, BlockResult, CheckBlockResult,
            DataCallback, DiscWriter,
        },
        SECTOR_SIZE,
    },
    io::{
        block::{Block, BlockKind, BlockReader, CISO_MAGIC},
        nkit::{JunkBits, NKitHeader},
    },
    read::{DiscMeta, DiscStream},
    util::{
        array_ref,
        digest::DigestManager,
        lfg::LaggedFibonacci,
        read::{box_to_bytes, read_arc},
        static_assert,
    },
    write::{DiscFinalization, DiscWriterWeight, FormatOptions, ProcessOptions},
    Error, Result, ResultContext,
};

pub const CISO_MAP_SIZE: usize = SECTOR_SIZE - 8;

/// CISO header (little endian)
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
struct CISOHeader {
    magic: MagicBytes,
    block_size: U32,
    block_present: [u8; CISO_MAP_SIZE],
}

static_assert!(size_of::<CISOHeader>() == SECTOR_SIZE);

#[derive(Clone)]
pub struct BlockReaderCISO {
    inner: Box<dyn DiscStream>,
    header: Arc<CISOHeader>,
    block_map: Arc<[u16; CISO_MAP_SIZE]>,
    nkit_header: Option<NKitHeader>,
}

impl BlockReaderCISO {
    pub fn new(mut inner: Box<dyn DiscStream>) -> Result<Box<Self>> {
        // Read header
        inner.seek(SeekFrom::Start(0)).context("Seeking to start")?;
        let header: Arc<CISOHeader> = read_arc(inner.as_mut()).context("Reading CISO header")?;
        if header.magic != CISO_MAGIC {
            return Err(Error::DiscFormat("Invalid CISO magic".to_string()));
        }

        // Build block map
        let mut block_map = <[u16; CISO_MAP_SIZE]>::new_box_zeroed()?;
        let mut block = 0u16;
        for (presence, out) in header.block_present.iter().zip(block_map.iter_mut()) {
            if *presence == 1 {
                *out = block;
                block += 1;
            } else {
                *out = u16::MAX;
            }
        }
        let file_size = SECTOR_SIZE as u64 + block as u64 * header.block_size.get() as u64;
        let len = inner.seek(SeekFrom::End(0)).context("Determining stream length")?;
        if file_size > len {
            return Err(Error::DiscFormat(format!(
                "CISO file size mismatch: expected at least {} bytes, got {}",
                file_size, len
            )));
        }

        // Read NKit header if present (after CISO data)
        let nkit_header = if len > file_size + 12 {
            inner.seek(SeekFrom::Start(file_size)).context("Seeking to NKit header")?;
            NKitHeader::try_read_from(inner.as_mut(), header.block_size.get(), true)
        } else {
            None
        };

        Ok(Box::new(Self { inner, header, block_map: Arc::from(block_map), nkit_header }))
    }
}

impl BlockReader for BlockReaderCISO {
    fn read_block(&mut self, out: &mut [u8], sector: u32) -> io::Result<Block> {
        let block_size = self.header.block_size.get();
        let block_idx = ((sector as u64 * SECTOR_SIZE as u64) / block_size as u64) as u32;
        if block_idx >= CISO_MAP_SIZE as u32 {
            // Out of bounds
            return Ok(Block::new(block_idx, block_size, BlockKind::None));
        }

        // Find the block in the map
        let phys_block = self.block_map[block_idx as usize];
        if phys_block == u16::MAX {
            // Check if block is junk data
            if self.nkit_header.as_ref().and_then(|h| h.is_junk_block(block_idx)).unwrap_or(false) {
                return Ok(Block::new(block_idx, block_size, BlockKind::Junk));
            };

            // Otherwise, read zeroes
            return Ok(Block::new(block_idx, block_size, BlockKind::Zero));
        }

        // Read block
        let file_offset = size_of::<CISOHeader>() as u64 + phys_block as u64 * block_size as u64;
        self.inner.seek(SeekFrom::Start(file_offset))?;
        self.inner.read_exact(out)?;

        Ok(Block::new(block_idx, block_size, BlockKind::Raw))
    }

    fn block_size(&self) -> u32 { self.header.block_size.get() }

    fn meta(&self) -> DiscMeta {
        let mut result = DiscMeta {
            format: Format::Ciso,
            block_size: Some(self.header.block_size.get()),
            ..Default::default()
        };
        if let Some(nkit_header) = &self.nkit_header {
            nkit_header.apply(&mut result);
        }
        result
    }
}

struct BlockProcessorCISO {
    inner: DiscReader,
    block_size: u32,
    decrypted_block: Box<[u8]>,
    lfg: LaggedFibonacci,
    disc_id: [u8; 4],
    disc_num: u8,
}

impl Clone for BlockProcessorCISO {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            block_size: self.block_size,
            decrypted_block: <[u8]>::new_box_zeroed_with_elems(self.block_size as usize).unwrap(),
            lfg: LaggedFibonacci::default(),
            disc_id: self.disc_id,
            disc_num: self.disc_num,
        }
    }
}

impl BlockProcessor for BlockProcessorCISO {
    type BlockMeta = CheckBlockResult;

    fn process_block(&mut self, block_idx: u32) -> io::Result<BlockResult<Self::BlockMeta>> {
        let block_size = self.block_size as usize;
        let input_position = block_idx as u64 * block_size as u64;
        self.inner.seek(SeekFrom::Start(input_position))?;
        let (block_data, disc_data) = read_block(&mut self.inner, block_size)?;

        // Check if block is zeroed or junk
        let result = match check_block(
            disc_data.as_ref(),
            &mut self.decrypted_block,
            input_position,
            self.inner.partitions(),
            &mut self.lfg,
            self.disc_id,
            self.disc_num,
        )? {
            CheckBlockResult::Normal => {
                BlockResult { block_idx, disc_data, block_data, meta: CheckBlockResult::Normal }
            }
            CheckBlockResult::Zeroed => BlockResult {
                block_idx,
                disc_data,
                block_data: Bytes::new(),
                meta: CheckBlockResult::Zeroed,
            },
            CheckBlockResult::Junk => BlockResult {
                block_idx,
                disc_data,
                block_data: Bytes::new(),
                meta: CheckBlockResult::Junk,
            },
        };
        Ok(result)
    }
}

#[derive(Clone)]
pub struct DiscWriterCISO {
    inner: DiscReader,
    block_size: u32,
    block_count: u32,
    disc_size: u64,
}

pub const DEFAULT_BLOCK_SIZE: u32 = 0x200000; // 2 MiB

impl DiscWriterCISO {
    pub fn new(inner: DiscReader, options: &FormatOptions) -> Result<Box<dyn DiscWriter>> {
        if options.format != Format::Ciso {
            return Err(Error::DiscFormat("Invalid format for CISO writer".to_string()));
        }
        if options.compression != Compression::None {
            return Err(Error::DiscFormat("CISO does not support compression".to_string()));
        }
        let block_size = DEFAULT_BLOCK_SIZE;

        let disc_size = inner.disc_size();
        let block_count = disc_size.div_ceil(block_size as u64) as u32;
        if block_count > CISO_MAP_SIZE as u32 {
            return Err(Error::DiscFormat(format!(
                "CISO block count exceeds maximum: {} > {}",
                block_count, CISO_MAP_SIZE
            )));
        }

        Ok(Box::new(Self { inner, block_size, block_count, disc_size }))
    }
}

impl DiscWriter for DiscWriterCISO {
    fn process(
        &self,
        data_callback: &mut DataCallback,
        options: &ProcessOptions,
    ) -> Result<DiscFinalization> {
        data_callback(BytesMut::zeroed(SECTOR_SIZE).freeze(), 0, self.disc_size)
            .context("Failed to write header")?;

        // Determine junk data values
        let disc_header = self.inner.header();
        let disc_id = *array_ref![disc_header.game_id, 0, 4];
        let disc_num = disc_header.disc_num;

        // Create hashers
        let digest = DigestManager::new(options);
        let block_size = self.block_size;
        let mut junk_bits = JunkBits::new(block_size);
        let mut input_position = 0;

        let mut block_count = 0;
        let mut header = CISOHeader::new_box_zeroed()?;
        header.magic = CISO_MAGIC;
        header.block_size = block_size.into();
        par_process(
            || BlockProcessorCISO {
                inner: self.inner.clone(),
                block_size,
                decrypted_block: <[u8]>::new_box_zeroed_with_elems(block_size as usize).unwrap(),
                lfg: LaggedFibonacci::default(),
                disc_id,
                disc_num,
            },
            self.block_count,
            options.processor_threads,
            |block| -> Result<()> {
                // Update hashers
                let disc_data_len = block.disc_data.len() as u64;
                digest.send(block.disc_data);

                // Check if block is zeroed or junk
                match block.meta {
                    CheckBlockResult::Normal => {
                        header.block_present[block.block_idx as usize] = 1;
                        block_count += 1;
                    }
                    CheckBlockResult::Zeroed => {}
                    CheckBlockResult::Junk => {
                        junk_bits.set(block.block_idx, true);
                    }
                }

                input_position += disc_data_len;
                data_callback(block.block_data, input_position, self.disc_size)
                    .with_context(|| format!("Failed to write block {}", block.block_idx))?;
                Ok(())
            },
        )?;

        // Collect hash results
        let digest_results = digest.finish();
        let mut nkit_header = NKitHeader {
            version: 2,
            size: Some(self.disc_size),
            crc32: None,
            md5: None,
            sha1: None,
            xxh64: None,
            junk_bits: Some(junk_bits),
            encrypted: true,
        };
        nkit_header.apply_digests(&digest_results);

        // Write NKit header after data
        let mut buffer = BytesMut::new().writer();
        nkit_header.write_to(&mut buffer).context("Writing NKit header")?;
        data_callback(buffer.into_inner().freeze(), self.disc_size, self.disc_size)
            .context("Failed to write NKit header")?;

        let header = Bytes::from(box_to_bytes(header));
        let mut finalization = DiscFinalization { header, ..Default::default() };
        finalization.apply_digests(&digest_results);
        Ok(finalization)
    }

    fn progress_bound(&self) -> u64 { self.disc_size }

    fn weight(&self) -> DiscWriterWeight { DiscWriterWeight::Medium }
}
