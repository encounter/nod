use std::{
    io,
    io::{BufRead, Seek, SeekFrom},
    sync::Arc,
};

use bytes::Bytes;
use tracing::warn;
use zerocopy::IntoBytes;

use crate::{
    common::{PartitionInfo, PartitionKind},
    disc::{
        direct::{DirectDiscReader, DirectDiscReaderMode},
        fst::{Fst, NodeKind},
        gcn::{read_fst, PartitionReaderGC},
        preloader::{Preloader, SectorGroup, SectorGroupLoader, SectorGroupRequest},
        wii::{
            PartitionReaderWii, WiiPartEntry, WiiPartGroup, WiiPartitionHeader, REGION_OFFSET,
            REGION_SIZE, WII_PART_GROUP_OFF,
        },
        DiscHeader, DL_DVD_SIZE, MINI_DVD_SIZE, SECTOR_GROUP_SIZE, SECTOR_SIZE, SL_DVD_SIZE,
    },
    io::block::BlockReader,
    read::{DiscMeta, DiscOptions, PartitionEncryption, PartitionOptions, PartitionReader},
    util::{
        impl_read_for_bufread,
        read::{read_arc, read_from, read_vec},
    },
    Error, Result, ResultContext,
};

pub struct DiscReader {
    io: Box<dyn BlockReader>,
    pos: u64,
    size: u64,
    mode: PartitionEncryption,
    disc_header: Arc<DiscHeader>,
    partitions: Arc<[PartitionInfo]>,
    region: Option<[u8; REGION_SIZE]>,
    sector_group: Option<SectorGroup>,
    preloader: Arc<Preloader>,
    alt_disc_header: Option<Arc<DiscHeader>>,
    alt_partitions: Option<Arc<[PartitionInfo]>>,
}

impl Clone for DiscReader {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            pos: 0,
            size: self.size,
            mode: self.mode,
            disc_header: self.disc_header.clone(),
            partitions: self.partitions.clone(),
            region: self.region,
            sector_group: None,
            preloader: self.preloader.clone(),
            alt_disc_header: self.alt_disc_header.clone(),
            alt_partitions: self.alt_partitions.clone(),
        }
    }
}

impl DiscReader {
    pub fn new(inner: Box<dyn BlockReader>, options: &DiscOptions) -> Result<Self> {
        let mut reader = DirectDiscReader::new(inner)?;

        let disc_header: Arc<DiscHeader> = read_arc(&mut reader).context("Reading disc header")?;
        let mut alt_disc_header = None;
        let mut region = None;
        let mut partitions = Arc::<[PartitionInfo]>::default();
        let mut alt_partitions = None;
        if disc_header.is_wii() {
            // Sanity check
            if disc_header.has_partition_encryption() && !disc_header.has_partition_hashes() {
                return Err(Error::DiscFormat(
                    "Wii disc is encrypted but has no partition hashes".to_string(),
                ));
            }
            if !disc_header.has_partition_hashes()
                && options.partition_encryption == PartitionEncryption::ForceEncrypted
            {
                return Err(Error::Other(
                    "Unsupported: Rebuilding encryption for Wii disc without hashes".to_string(),
                ));
            }

            // Read region info
            reader.seek(SeekFrom::Start(REGION_OFFSET)).context("Seeking to region info")?;
            region = Some(read_from(&mut reader).context("Reading region info")?);

            // Read partition info
            partitions = Arc::from(read_partition_info(&mut reader, disc_header.clone())?);

            // Update disc header with encryption mode
            if matches!(
                options.partition_encryption,
                PartitionEncryption::ForceDecrypted | PartitionEncryption::ForceEncrypted
            ) {
                let mut disc_header = Box::new(disc_header.as_ref().clone());
                let mut partitions = Box::<[PartitionInfo]>::from(partitions.as_ref());
                disc_header.no_partition_encryption = match options.partition_encryption {
                    PartitionEncryption::ForceDecrypted => 1,
                    PartitionEncryption::ForceEncrypted => 0,
                    _ => unreachable!(),
                };
                for partition in &mut partitions {
                    partition.has_encryption = disc_header.has_partition_encryption();
                }
                alt_disc_header = Some(Arc::from(disc_header));
                alt_partitions = Some(Arc::from(partitions));
            }
        } else if !disc_header.is_gamecube() {
            return Err(Error::DiscFormat("Invalid disc header".to_string()));
        }

        // Calculate disc size
        let io = reader.into_inner();
        let size = io.meta().disc_size.unwrap_or_else(|| guess_disc_size(&partitions));
        let preloader = Preloader::new(
            SectorGroupLoader::new(io.clone(), disc_header.clone(), partitions.clone()),
            options.preloader_threads,
        );
        Ok(Self {
            io,
            pos: 0,
            size,
            mode: options.partition_encryption,
            disc_header,
            partitions,
            region,
            sector_group: None,
            preloader,
            alt_disc_header,
            alt_partitions,
        })
    }

    #[inline]
    pub fn reset(&mut self) { self.pos = 0; }

    #[inline]
    pub fn position(&self) -> u64 { self.pos }

    #[inline]
    pub fn disc_size(&self) -> u64 { self.size }

    #[inline]
    pub fn header(&self) -> &DiscHeader {
        self.alt_disc_header.as_ref().unwrap_or(&self.disc_header)
    }

    #[inline]
    pub fn region(&self) -> Option<&[u8; REGION_SIZE]> { self.region.as_ref() }

    #[inline]
    pub fn partitions(&self) -> &[PartitionInfo] {
        self.alt_partitions.as_deref().unwrap_or(&self.partitions)
    }

    #[inline]
    pub fn meta(&self) -> DiscMeta { self.io.meta() }

    /// Opens a new, decrypted partition read stream for the specified partition index.
    pub fn open_partition(
        &self,
        index: usize,
        options: &PartitionOptions,
    ) -> Result<Box<dyn PartitionReader>> {
        if self.disc_header.is_gamecube() {
            if index == 0 {
                Ok(PartitionReaderGC::new(
                    self.io.clone(),
                    self.preloader.clone(),
                    self.disc_size(),
                )?)
            } else {
                Err(Error::DiscFormat("GameCube discs only have one partition".to_string()))
            }
        } else if let Some(part) = self.partitions.get(index) {
            Ok(PartitionReaderWii::new(self.io.clone(), self.preloader.clone(), part, options)?)
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
    ) -> Result<Box<dyn PartitionReader>> {
        if self.disc_header.is_gamecube() {
            if kind == PartitionKind::Data {
                Ok(PartitionReaderGC::new(
                    self.io.clone(),
                    self.preloader.clone(),
                    self.disc_size(),
                )?)
            } else {
                Err(Error::DiscFormat("GameCube discs only have a data partition".to_string()))
            }
        } else if let Some(part) = self.partitions.iter().find(|v| v.kind == kind) {
            Ok(PartitionReaderWii::new(self.io.clone(), self.preloader.clone(), part, options)?)
        } else {
            Err(Error::DiscFormat(format!("Partition type {kind} not found")))
        }
    }

    pub fn fill_buf_internal(&mut self) -> io::Result<Bytes> {
        if self.pos >= self.size {
            return Ok(Bytes::new());
        }

        // Read from modified disc header
        if self.pos < size_of::<DiscHeader>() as u64 {
            if let Some(alt_disc_header) = &self.alt_disc_header {
                return Ok(Bytes::copy_from_slice(
                    &alt_disc_header.as_bytes()[self.pos as usize..],
                ));
            }
        }

        // Build sector group request
        let abs_sector = (self.pos / SECTOR_SIZE as u64) as u32;
        let (request, abs_group_sector, max_groups) = if let Some(partition) =
            self.partitions.iter().find(|part| part.data_contains_sector(abs_sector))
        {
            let group_idx = (abs_sector - partition.data_start_sector) / 64;
            let abs_group_sector = partition.data_start_sector + group_idx * 64;
            let max_groups = (partition.data_end_sector - partition.data_start_sector).div_ceil(64);
            let request = SectorGroupRequest {
                group_idx,
                partition_idx: Some(partition.index as u8),
                mode: self.mode,
            };
            (request, abs_group_sector, max_groups)
        } else {
            let group_idx = abs_sector / 64;
            let abs_group_sector = group_idx * 64;
            let max_groups = self.size.div_ceil(SECTOR_GROUP_SIZE as u64) as u32;
            let request = SectorGroupRequest { group_idx, partition_idx: None, mode: self.mode };
            (request, abs_group_sector, max_groups)
        };

        // Load sector group
        let sector_group = if matches!(&self.sector_group, Some(sector_group) if sector_group.request == request)
        {
            // We can improve this in Rust 2024 with `if_let_rescope`
            // https://github.com/rust-lang/rust/issues/124085
            self.sector_group.as_ref().unwrap()
        } else {
            self.sector_group.insert(self.preloader.fetch(request, max_groups)?)
        };

        // Calculate the number of consecutive sectors in the group
        let group_sector = abs_sector - abs_group_sector;
        let consecutive_sectors = sector_group.consecutive_sectors(group_sector);
        if consecutive_sectors == 0 {
            return Ok(Bytes::new());
        }
        let num_sectors = group_sector + consecutive_sectors;

        // Read from sector group buffer
        let group_start = abs_group_sector as u64 * SECTOR_SIZE as u64;
        let offset = (self.pos - group_start) as usize;
        let end = (num_sectors as u64 * SECTOR_SIZE as u64).min(self.size - group_start) as usize;
        Ok(sector_group.data.slice(offset..end))
    }
}

impl BufRead for DiscReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.size {
            return Ok(&[]);
        }

        // Read from modified disc header
        if self.pos < size_of::<DiscHeader>() as u64 {
            if let Some(alt_disc_header) = &self.alt_disc_header {
                return Ok(&alt_disc_header.as_bytes()[self.pos as usize..]);
            }
        }

        // Build sector group request
        let abs_sector = (self.pos / SECTOR_SIZE as u64) as u32;
        let (request, abs_group_sector, max_groups) = if let Some(partition) =
            self.partitions.iter().find(|part| part.data_contains_sector(abs_sector))
        {
            let group_idx = (abs_sector - partition.data_start_sector) / 64;
            let abs_group_sector = partition.data_start_sector + group_idx * 64;
            let max_groups = (partition.data_end_sector - partition.data_start_sector).div_ceil(64);
            let request = SectorGroupRequest {
                group_idx,
                partition_idx: Some(partition.index as u8),
                mode: self.mode,
            };
            (request, abs_group_sector, max_groups)
        } else {
            let group_idx = abs_sector / 64;
            let abs_group_sector = group_idx * 64;
            let max_groups = self.size.div_ceil(SECTOR_GROUP_SIZE as u64) as u32;
            let request = SectorGroupRequest { group_idx, partition_idx: None, mode: self.mode };
            (request, abs_group_sector, max_groups)
        };

        // Load sector group
        let sector_group = if matches!(&self.sector_group, Some(sector_group) if sector_group.request == request)
        {
            // We can improve this in Rust 2024 with `if_let_rescope`
            // https://github.com/rust-lang/rust/issues/124085
            self.sector_group.as_ref().unwrap()
        } else {
            self.sector_group.insert(self.preloader.fetch(request, max_groups)?)
        };

        // Calculate the number of consecutive sectors in the group
        let group_sector = abs_sector - abs_group_sector;
        let consecutive_sectors = sector_group.consecutive_sectors(group_sector);
        if consecutive_sectors == 0 {
            return Ok(&[]);
        }
        let num_sectors = group_sector + consecutive_sectors;

        // Read from sector group buffer
        let group_start = abs_group_sector as u64 * SECTOR_SIZE as u64;
        let offset = (self.pos - group_start) as usize;
        let end = (num_sectors as u64 * SECTOR_SIZE as u64).min(self.size - group_start) as usize;
        Ok(&sector_group.data[offset..end])
    }

    #[inline]
    fn consume(&mut self, amt: usize) { self.pos += amt as u64; }
}

impl_read_for_bufread!(DiscReader);

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

fn read_partition_info(
    reader: &mut DirectDiscReader,
    disc_header: Arc<DiscHeader>,
) -> Result<Vec<PartitionInfo>> {
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
            let header: Arc<WiiPartitionHeader> = read_arc(reader)
                .with_context(|| format!("Reading partition header {group_idx}:{part_idx}"))?;

            let key = header.ticket.decrypt_title_key()?;
            let start_offset = entry.offset();
            if start_offset % SECTOR_SIZE as u64 != 0 {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} offset is not sector aligned",
                )));
            }

            let data_start_offset = entry.offset() + header.data_off();
            let data_size = header.data_size();
            let data_end_offset = data_start_offset + data_size;
            if data_start_offset % SECTOR_SIZE as u64 != 0
                || data_end_offset % SECTOR_SIZE as u64 != 0
            {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} data is not sector aligned",
                )));
            }
            let start_sector = (start_offset / SECTOR_SIZE as u64) as u32;
            let data_start_sector = (data_start_offset / SECTOR_SIZE as u64) as u32;
            let mut data_end_sector = (data_end_offset / SECTOR_SIZE as u64) as u32;

            reader.reset(DirectDiscReaderMode::Partition {
                disc_header: disc_header.clone(),
                data_start_sector,
                key,
            });
            let partition_disc_header: Arc<DiscHeader> =
                read_arc(reader).context("Reading partition disc header")?;
            let partition_header = read_arc(reader).context("Reading partition header")?;
            if partition_disc_header.is_wii() {
                let raw_fst = read_fst(reader, &partition_header, true)?;
                let fst = Fst::new(&raw_fst)?;
                let max_fst_offset = fst
                    .nodes
                    .iter()
                    .filter_map(|n| match n.kind() {
                        NodeKind::File => Some(n.offset(true) + n.length() as u64),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                if max_fst_offset > data_size {
                    if data_size == 0 {
                        // Guess data size for decrypted partitions
                        data_end_sector = max_fst_offset.div_ceil(SECTOR_SIZE as u64) as u32;
                    } else {
                        return Err(Error::DiscFormat(format!(
                            "Partition {group_idx}:{part_idx} FST exceeds data size",
                        )));
                    }
                }
            } else {
                warn!("Partition {group_idx}:{part_idx} is not valid");
            }
            reader.reset(DirectDiscReaderMode::Raw);

            part_info.push(PartitionInfo {
                index: part_info.len(),
                kind: entry.kind.get().into(),
                start_sector,
                data_start_sector,
                data_end_sector,
                key,
                header,
                disc_header: partition_disc_header,
                partition_header,
                has_encryption: disc_header.has_partition_encryption(),
                has_hashes: disc_header.has_partition_hashes(),
            });
        }
    }
    Ok(part_info)
}

fn guess_disc_size(part_info: &[PartitionInfo]) -> u64 {
    let max_offset = part_info
        .iter()
        .map(|v| v.data_end_sector as u64 * SECTOR_SIZE as u64)
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
