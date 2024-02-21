use std::{
    cmp::min,
    io,
    io::{Read, Seek, SeekFrom},
};

use zerocopy::FromZeroes;

use crate::{
    disc::{
        hashes::{rebuild_hashes, HashTable},
        partition::PartitionReader,
        wii::{WiiPartEntry, WiiPartGroup, WiiPartitionHeader, WII_PART_GROUP_OFF},
        DL_DVD_SIZE, MINI_DVD_SIZE, SL_DVD_SIZE,
    },
    io::block::{BPartitionInfo, Block, BlockIO},
    util::read::{read_box, read_from, read_vec},
    DiscHeader, Error, PartitionHeader, PartitionKind, Result, ResultContext, SECTOR_SIZE,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EncryptionMode {
    Encrypted,
    Decrypted,
}

pub struct DiscReader {
    pub(crate) io: Box<dyn BlockIO>,
    block: Option<Block>,
    block_buf: Box<[u8]>,
    block_idx: u32,
    sector_buf: Box<[u8; SECTOR_SIZE]>,
    sector_idx: u32,
    pos: u64,
    mode: EncryptionMode,
    disc_header: Box<DiscHeader>,
    pub(crate) partitions: Vec<BPartitionInfo>,
    hash_tables: Vec<HashTable>,
}

impl Clone for DiscReader {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            block: None,
            block_buf: <u8>::new_box_slice_zeroed(self.block_buf.len()),
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed(),
            sector_idx: u32::MAX,
            pos: 0,
            mode: self.mode,
            disc_header: self.disc_header.clone(),
            partitions: self.partitions.clone(),
            hash_tables: self.hash_tables.clone(),
        }
    }
}

impl DiscReader {
    pub fn new(inner: Box<dyn BlockIO>, mode: EncryptionMode) -> Result<Self> {
        let block_size = inner.block_size();
        let meta = inner.meta()?;
        let mut reader = Self {
            io: inner,
            block: None,
            block_buf: <u8>::new_box_slice_zeroed(block_size as usize),
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed(),
            sector_idx: u32::MAX,
            pos: 0,
            mode,
            disc_header: DiscHeader::new_box_zeroed(),
            partitions: vec![],
            hash_tables: vec![],
        };
        let disc_header: Box<DiscHeader> = read_box(&mut reader).context("Reading disc header")?;
        reader.disc_header = disc_header;
        if reader.disc_header.is_wii() {
            reader.partitions = read_partition_info(&mut reader)?;
            // Rebuild hashes if the format requires it
            if mode == EncryptionMode::Encrypted && meta.needs_hash_recovery {
                rebuild_hashes(&mut reader)?;
            }
        }
        reader.reset();
        Ok(reader)
    }

    pub fn reset(&mut self) {
        self.block = None;
        self.block_buf.fill(0);
        self.block_idx = u32::MAX;
        self.sector_buf.fill(0);
        self.sector_idx = u32::MAX;
        self.pos = 0;
    }

    pub fn disc_size(&self) -> u64 {
        self.io
            .meta()
            .ok()
            .and_then(|m| m.disc_size)
            .unwrap_or_else(|| guess_disc_size(&self.partitions))
    }

    pub fn header(&self) -> &DiscHeader { &self.disc_header }

    pub fn partitions(&self) -> &[BPartitionInfo] { &self.partitions }
}

impl Read for DiscReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let block_idx = (self.pos / self.block_buf.len() as u64) as u32;
        let abs_sector = (self.pos / SECTOR_SIZE as u64) as u32;

        let partition = if self.disc_header.is_wii() {
            self.partitions.iter().find(|part| {
                abs_sector >= part.data_start_sector && abs_sector < part.data_end_sector
            })
        } else {
            None
        };

        // Read new block
        if block_idx != self.block_idx {
            self.block = self.io.read_block(self.block_buf.as_mut(), block_idx, partition)?;
            self.block_idx = block_idx;
        }

        // Read new sector into buffer
        if abs_sector != self.sector_idx {
            let Some(block) = &self.block else {
                return Ok(0);
            };
            if let Some(partition) = partition {
                match self.mode {
                    EncryptionMode::Decrypted => block.decrypt(
                        &mut self.sector_buf,
                        self.block_buf.as_ref(),
                        block_idx,
                        abs_sector,
                        partition,
                    )?,
                    EncryptionMode::Encrypted => block.encrypt(
                        &mut self.sector_buf,
                        self.block_buf.as_ref(),
                        block_idx,
                        abs_sector,
                        partition,
                    )?,
                }
            } else {
                block.copy_raw(
                    &mut self.sector_buf,
                    self.block_buf.as_ref(),
                    block_idx,
                    abs_sector,
                    &self.disc_header,
                )?;
            }
            self.sector_idx = abs_sector;
        }

        // Read from sector buffer
        let offset = (self.pos % SECTOR_SIZE as u64) as usize;
        let len = min(buf.len(), SECTOR_SIZE - offset);
        buf[..len].copy_from_slice(&self.sector_buf[offset..offset + len]);
        self.pos += len as u64;
        Ok(len)
    }
}

impl Seek for DiscReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "BlockIOReader: SeekFrom::End is not supported".to_string(),
                ));
            }
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };
        Ok(self.pos)
    }
}

fn read_partition_info(stream: &mut DiscReader) -> crate::Result<Vec<BPartitionInfo>> {
    stream.seek(SeekFrom::Start(WII_PART_GROUP_OFF)).context("Seeking to partition groups")?;
    let part_groups: [WiiPartGroup; 4] = read_from(stream).context("Reading partition groups")?;
    let mut part_info = Vec::new();
    for (group_idx, group) in part_groups.iter().enumerate() {
        let part_count = group.part_count.get();
        if part_count == 0 {
            continue;
        }
        stream
            .seek(SeekFrom::Start(group.part_entry_off()))
            .with_context(|| format!("Seeking to partition group {group_idx}"))?;
        let entries: Vec<WiiPartEntry> = read_vec(stream, part_count as usize)
            .with_context(|| format!("Reading partition group {group_idx}"))?;
        for (part_idx, entry) in entries.iter().enumerate() {
            let offset = entry.offset();
            stream
                .seek(SeekFrom::Start(offset))
                .with_context(|| format!("Seeking to partition data {group_idx}:{part_idx}"))?;
            let header: Box<WiiPartitionHeader> = read_box(stream)
                .with_context(|| format!("Reading partition header {group_idx}:{part_idx}"))?;

            let key = header.ticket.decrypt_title_key()?;
            let start_offset = entry.offset();
            if start_offset % SECTOR_SIZE as u64 != 0 {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} offset is not sector aligned",
                )));
            }
            let data_start_offset = entry.offset() + header.data_off();
            let data_end_offset = data_start_offset + header.data_size();
            if data_start_offset % SECTOR_SIZE as u64 != 0
                || data_end_offset % SECTOR_SIZE as u64 != 0
            {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} data is not sector aligned",
                )));
            }
            let mut info = BPartitionInfo {
                index: part_info.len() as u32,
                kind: entry.kind.get().into(),
                start_sector: (start_offset / SECTOR_SIZE as u64) as u32,
                data_start_sector: (data_start_offset / SECTOR_SIZE as u64) as u32,
                data_end_sector: (data_end_offset / SECTOR_SIZE as u64) as u32,
                key,
                header,
                disc_header: DiscHeader::new_box_zeroed(),
                partition_header: PartitionHeader::new_box_zeroed(),
                hash_table: None,
            };

            let mut partition_reader = PartitionReader::new(stream.io.clone(), &info)?;
            info.disc_header = read_box(&mut partition_reader).context("Reading disc header")?;
            info.partition_header =
                read_box(&mut partition_reader).context("Reading partition header")?;

            part_info.push(info);
        }
    }
    Ok(part_info)
}

fn guess_disc_size(part_info: &[BPartitionInfo]) -> u64 {
    let max_offset = part_info
        .iter()
        .flat_map(|v| {
            let offset = v.start_sector as u64 * SECTOR_SIZE as u64;
            [
                offset + v.header.tmd_off() + v.header.tmd_size(),
                offset + v.header.cert_chain_off() + v.header.cert_chain_size(),
                offset + v.header.h3_table_off() + v.header.h3_table_size(),
                offset + v.header.data_off() + v.header.data_size(),
            ]
        })
        .max()
        .unwrap_or(0x50000);
    if max_offset <= MINI_DVD_SIZE && !part_info.iter().any(|v| v.kind == PartitionKind::Data) {
        // Datel disc
        MINI_DVD_SIZE
    } else if max_offset < SL_DVD_SIZE {
        SL_DVD_SIZE
    } else {
        DL_DVD_SIZE
    }
}
