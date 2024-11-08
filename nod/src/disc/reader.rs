use std::{
    io,
    io::{BufRead, Read, Seek, SeekFrom},
};

use zerocopy::{FromBytes, FromZeros};

use super::{
    gcn::PartitionGC,
    hashes::{rebuild_hashes, HashTable},
    wii::{PartitionWii, WiiPartEntry, WiiPartGroup, WiiPartitionHeader, WII_PART_GROUP_OFF},
    DiscHeader, PartitionBase, PartitionHeader, PartitionKind, DL_DVD_SIZE, MINI_DVD_SIZE,
    REGION_SIZE, SL_DVD_SIZE,
};
use crate::{
    disc::wii::REGION_OFFSET,
    io::block::{Block, BlockIO, PartitionInfo},
    util::read::{read_box, read_from, read_vec},
    DiscMeta, Error, OpenOptions, PartitionEncryptionMode, PartitionOptions, Result, ResultContext,
    SECTOR_SIZE,
};

pub struct DiscReader {
    io: Box<dyn BlockIO>,
    block: Block,
    block_buf: Box<[u8]>,
    block_idx: u32,
    sector_buf: Box<[u8; SECTOR_SIZE]>,
    sector_idx: u32,
    pos: u64,
    mode: PartitionEncryptionMode,
    disc_header: Box<DiscHeader>,
    pub(crate) partitions: Vec<PartitionInfo>,
    hash_tables: Vec<HashTable>,
    region: Option<[u8; REGION_SIZE]>,
}

impl Clone for DiscReader {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            block: Block::default(),
            block_buf: <[u8]>::new_box_zeroed_with_elems(self.block_buf.len()).unwrap(),
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed().unwrap(),
            sector_idx: u32::MAX,
            pos: 0,
            mode: self.mode,
            disc_header: self.disc_header.clone(),
            partitions: self.partitions.clone(),
            hash_tables: self.hash_tables.clone(),
            region: self.region,
        }
    }
}

impl DiscReader {
    pub fn new(inner: Box<dyn BlockIO>, options: &OpenOptions) -> Result<Self> {
        let block_size = inner.block_size();
        let meta = inner.meta();
        let mut reader = Self {
            io: inner,
            block: Block::default(),
            block_buf: <[u8]>::new_box_zeroed_with_elems(block_size as usize)?,
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed()?,
            sector_idx: u32::MAX,
            pos: 0,
            mode: options.partition_encryption,
            disc_header: DiscHeader::new_box_zeroed()?,
            partitions: vec![],
            hash_tables: vec![],
            region: None,
        };
        let disc_header: Box<DiscHeader> = read_box(&mut reader).context("Reading disc header")?;
        reader.disc_header = disc_header;
        if reader.disc_header.is_wii() {
            if reader.disc_header.has_partition_encryption()
                && !reader.disc_header.has_partition_hashes()
            {
                return Err(Error::DiscFormat(
                    "Wii disc is encrypted but has no partition hashes".to_string(),
                ));
            }
            if !reader.disc_header.has_partition_hashes()
                && options.partition_encryption == PartitionEncryptionMode::ForceEncrypted
            {
                return Err(Error::Other(
                    "Unsupported: Rebuilding encryption for Wii disc without hashes".to_string(),
                ));
            }
            reader.seek(SeekFrom::Start(REGION_OFFSET)).context("Seeking to region info")?;
            reader.region = Some(read_from(&mut reader).context("Reading region info")?);
            reader.partitions = read_partition_info(&mut reader)?;
            // Rebuild hashes if the format requires it
            if options.partition_encryption != PartitionEncryptionMode::AsIs
                && meta.needs_hash_recovery
                && reader.disc_header.has_partition_hashes()
            {
                rebuild_hashes(&mut reader)?;
            }
        }
        reader.reset();
        Ok(reader)
    }

    pub fn reset(&mut self) {
        self.block = Block::default();
        self.block_buf.fill(0);
        self.block_idx = u32::MAX;
        self.sector_buf.fill(0);
        self.sector_idx = u32::MAX;
        self.pos = 0;
    }

    pub fn disc_size(&self) -> u64 {
        self.io.meta().disc_size.unwrap_or_else(|| guess_disc_size(&self.partitions))
    }

    #[inline]
    pub fn header(&self) -> &DiscHeader { &self.disc_header }

    #[inline]
    pub fn region(&self) -> Option<&[u8; REGION_SIZE]> { self.region.as_ref() }

    #[inline]
    pub fn partitions(&self) -> &[PartitionInfo] { &self.partitions }

    #[inline]
    pub fn meta(&self) -> DiscMeta { self.io.meta() }

    /// Opens a new, decrypted partition read stream for the specified partition index.
    pub fn open_partition(
        &self,
        index: usize,
        options: &PartitionOptions,
    ) -> Result<Box<dyn PartitionBase>> {
        if self.disc_header.is_gamecube() {
            if index == 0 {
                Ok(PartitionGC::new(self.io.clone(), self.disc_header.clone())?)
            } else {
                Err(Error::DiscFormat("GameCube discs only have one partition".to_string()))
            }
        } else if let Some(part) = self.partitions.get(index) {
            Ok(PartitionWii::new(self.io.clone(), self.disc_header.clone(), part, options)?)
        } else {
            Err(Error::DiscFormat(format!("Partition {index} not found")))
        }
    }

    /// Opens a new, decrypted partition read stream for the first partition matching
    /// the specified kind.
    pub fn open_partition_kind(
        &self,
        kind: PartitionKind,
        options: &PartitionOptions,
    ) -> Result<Box<dyn PartitionBase>> {
        if self.disc_header.is_gamecube() {
            if kind == PartitionKind::Data {
                Ok(PartitionGC::new(self.io.clone(), self.disc_header.clone())?)
            } else {
                Err(Error::DiscFormat("GameCube discs only have a data partition".to_string()))
            }
        } else if let Some(part) = self.partitions.iter().find(|v| v.kind == kind) {
            Ok(PartitionWii::new(self.io.clone(), self.disc_header.clone(), part, options)?)
        } else {
            Err(Error::DiscFormat(format!("Partition type {kind} not found")))
        }
    }
}

impl BufRead for DiscReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
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
            match (self.mode, partition, self.disc_header.has_partition_encryption()) {
                (PartitionEncryptionMode::Original, Some(partition), true)
                | (PartitionEncryptionMode::ForceEncrypted, Some(partition), _) => {
                    self.block.encrypt(
                        self.sector_buf.as_mut(),
                        self.block_buf.as_ref(),
                        abs_sector,
                        partition,
                    )?;
                }
                (PartitionEncryptionMode::ForceDecrypted, Some(partition), _) => {
                    self.block.decrypt(
                        self.sector_buf.as_mut(),
                        self.block_buf.as_ref(),
                        abs_sector,
                        partition,
                    )?;
                }
                (PartitionEncryptionMode::AsIs, _, _) | (_, None, _) | (_, _, false) => {
                    self.block.copy_raw(
                        self.sector_buf.as_mut(),
                        self.block_buf.as_ref(),
                        abs_sector,
                        &self.disc_header,
                    )?;
                }
            }
            self.sector_idx = abs_sector;

            if self.sector_idx == 0
                && self.disc_header.is_wii()
                && matches!(
                    self.mode,
                    PartitionEncryptionMode::ForceDecrypted
                        | PartitionEncryptionMode::ForceEncrypted
                )
            {
                let (disc_header, _) = DiscHeader::mut_from_prefix(self.sector_buf.as_mut())
                    .expect("Invalid disc header alignment");
                disc_header.no_partition_encryption = match self.mode {
                    PartitionEncryptionMode::ForceDecrypted => 1,
                    PartitionEncryptionMode::ForceEncrypted => 0,
                    _ => unreachable!(),
                };
            }
        }

        // Read from sector buffer
        let offset = (self.pos % SECTOR_SIZE as u64) as usize;
        Ok(&self.sector_buf[offset..])
    }

    #[inline]
    fn consume(&mut self, amt: usize) { self.pos += amt as u64; }
}

impl Read for DiscReader {
    #[inline]
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let buf = self.fill_buf()?;
        let len = buf.len().min(out.len());
        out[..len].copy_from_slice(&buf[..len]);
        self.consume(len);
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

fn read_partition_info(reader: &mut DiscReader) -> Result<Vec<PartitionInfo>> {
    reader.seek(SeekFrom::Start(WII_PART_GROUP_OFF)).context("Seeking to partition groups")?;
    let part_groups: [WiiPartGroup; 4] = read_from(reader).context("Reading partition groups")?;
    let mut part_info = Vec::new();
    for (group_idx, group) in part_groups.iter().enumerate() {
        let part_count = group.part_count.get();
        if part_count == 0 {
            continue;
        }
        reader
            .seek(SeekFrom::Start(group.part_entry_off()))
            .with_context(|| format!("Seeking to partition group {group_idx}"))?;
        let entries: Vec<WiiPartEntry> = read_vec(reader, part_count as usize)
            .with_context(|| format!("Reading partition group {group_idx}"))?;
        for (part_idx, entry) in entries.iter().enumerate() {
            let offset = entry.offset();
            reader
                .seek(SeekFrom::Start(offset))
                .with_context(|| format!("Seeking to partition data {group_idx}:{part_idx}"))?;
            let header: Box<WiiPartitionHeader> = read_box(reader)
                .with_context(|| format!("Reading partition header {group_idx}:{part_idx}"))?;

            let key = header.ticket.decrypt_title_key()?;
            let start_offset = entry.offset();
            if start_offset % SECTOR_SIZE as u64 != 0 {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} offset is not sector aligned",
                )));
            }

            let disc_header = reader.header();
            let data_start_offset = entry.offset() + header.data_off();
            let mut data_size = header.data_size();
            if data_size == 0 {
                // Read until next partition or end of disc
                // TODO: handle multiple partition groups
                data_size = entries
                    .get(part_idx + 1)
                    .map(|part| part.offset() - data_start_offset)
                    .unwrap_or(reader.disc_size() - data_start_offset);
            }
            let data_end_offset = data_start_offset + data_size;
            if data_start_offset % SECTOR_SIZE as u64 != 0
                || data_end_offset % SECTOR_SIZE as u64 != 0
            {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} data is not sector aligned",
                )));
            }
            let mut info = PartitionInfo {
                index: part_info.len(),
                kind: entry.kind.get().into(),
                start_sector: (start_offset / SECTOR_SIZE as u64) as u32,
                data_start_sector: (data_start_offset / SECTOR_SIZE as u64) as u32,
                data_end_sector: (data_end_offset / SECTOR_SIZE as u64) as u32,
                key,
                header,
                disc_header: DiscHeader::new_box_zeroed()?,
                partition_header: PartitionHeader::new_box_zeroed()?,
                hash_table: None,
                has_encryption: disc_header.has_partition_encryption(),
                has_hashes: disc_header.has_partition_hashes(),
            };

            let mut partition_reader = PartitionWii::new(
                reader.io.clone(),
                reader.disc_header.clone(),
                &info,
                &PartitionOptions { validate_hashes: false },
            )?;
            info.disc_header = read_box(&mut partition_reader).context("Reading disc header")?;
            info.partition_header =
                read_box(&mut partition_reader).context("Reading partition header")?;

            part_info.push(info);
        }
    }
    Ok(part_info)
}

fn guess_disc_size(part_info: &[PartitionInfo]) -> u64 {
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
    // TODO add FST offsets (decrypted partitions)
    if max_offset <= MINI_DVD_SIZE && !part_info.iter().any(|v| v.kind == PartitionKind::Data) {
        // Datel disc
        MINI_DVD_SIZE
    } else if max_offset < SL_DVD_SIZE {
        SL_DVD_SIZE
    } else {
        DL_DVD_SIZE
    }
}
