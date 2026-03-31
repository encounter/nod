#![allow(missing_docs, unused)] // TODO
use std::{
    io,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    sync::Arc,
};

use zerocopy::{FromBytes, IntoBytes};

use super::gc::{
    FileCallback, FileInfo, GCPartitionBuilder, GCPartitionStream, GCPartitionWriter,
    PartitionOverrides,
};
use crate::{
    Error, Result, ResultContext,
    common::KeyBytes,
    disc::{
        BB2_OFFSET, BOOT_SIZE, BootHeader, DiscHeader, SECTOR_GROUP_SIZE, SECTOR_SIZE,
        hashes::hash_sector_group,
        wii::{
            H3_TABLE_SIZE, HASHES_SIZE, REGION_OFFSET, REGION_SIZE, SECTOR_DATA_SIZE, Ticket,
            WiiPartEntry, WiiPartGroup,
        },
    },
    read::{CloneableStream, DiscStream, NonCloneableStream},
    util::{aes::encrypt_sector, digest::sha1_hash},
};

const PARTITION_START: u64 = 0x50000;
const PARTITION_ENTRY_OFFSET: u64 = 0x40020;
const TMD_PART_OFFSET: u64 = 0x2C0;
const H3_TABLE_PART_OFFSET: u64 = 0x8000;
const DATA_PART_OFFSET: u64 = 0x20000;
const DATA_START: u64 = PARTITION_START + DATA_PART_OFFSET;
const DATA_PART_KIND: u32 = 0;

pub struct WiiPartitionBuilder {
    gc_builder: GCPartitionBuilder,
    ticket: Vec<u8>,
    tmd: Vec<u8>,
    cert_chain: Vec<u8>,
    region: Option<[u8; REGION_SIZE]>,
}

pub struct WiiPartitionWriter {
    gc_writer: GCPartitionWriter,
    ticket: Vec<u8>,
    tmd: Vec<u8>,
    cert_chain: Vec<u8>,
    title_key: KeyBytes,
    region: Option<[u8; REGION_SIZE]>,
}

#[derive(Clone)]
struct WiiDiscMeta {
    outer_area: Arc<[u8]>,
    partition_header: Arc<[u8]>,
    title_key: KeyBytes,
    num_sectors: u32,
    disc_size: u64,
}

pub(crate) struct WiiDiscStream<Cb> {
    meta: Arc<WiiDiscMeta>,
    gc_stream: GCPartitionStream<Cb>,
    pos: u64,
    cached_group: Option<(u32, Box<[u8]>)>,
}

impl WiiPartitionBuilder {
    pub fn new(
        overrides: PartitionOverrides,
        ticket: Vec<u8>,
        tmd: Vec<u8>,
        cert_chain: Vec<u8>,
        region: Option<[u8; REGION_SIZE]>,
    ) -> Self {
        Self {
            gc_builder: GCPartitionBuilder::new(true, overrides),
            ticket,
            tmd,
            cert_chain,
            region,
        }
    }

    #[inline]
    pub fn set_disc_header(&mut self, disc_header: Box<DiscHeader>) {
        self.gc_builder.set_disc_header(disc_header);
    }

    #[inline]
    pub fn set_boot_header(&mut self, boot_header: Box<BootHeader>) {
        self.gc_builder.set_boot_header(boot_header);
    }

    #[inline]
    pub fn add_file(&mut self, info: FileInfo) -> Result<()> { self.gc_builder.add_file(info) }

    #[inline]
    pub fn add_junk_file(&mut self, name: String) { self.gc_builder.add_junk_file(name); }

    pub fn build(
        &self,
        sys_file_callback: impl FnMut(&mut dyn Write, &str) -> io::Result<()>,
    ) -> Result<WiiPartitionWriter> {
        let ticket = Ticket::ref_from_bytes(self.ticket.as_slice())
            .map_err(|_| Error::Other("Invalid ticket data".to_string()))?;
        let title_key = ticket.decrypt_title_key()?;
        let gc_writer = self.gc_builder.build(sys_file_callback)?;
        Ok(WiiPartitionWriter {
            gc_writer,
            ticket: self.ticket.clone(),
            tmd: self.tmd.clone(),
            cert_chain: self.cert_chain.clone(),
            title_key,
            region: self.region,
        })
    }
}

impl WiiPartitionWriter {
    pub fn into_cloneable_stream<Cb>(self, file_callback: Cb) -> Result<Box<dyn DiscStream>>
    where Cb: FileCallback + Clone + 'static {
        let (meta, gc_stream) = self.prepare_stream(file_callback)?;
        Ok(Box::new(CloneableStream::new(WiiDiscStream {
            meta: Arc::new(meta),
            gc_stream,
            pos: 0,
            cached_group: None,
        })))
    }

    pub fn into_non_cloneable_stream<Cb>(self, file_callback: Cb) -> Result<Box<dyn DiscStream>>
    where Cb: FileCallback + 'static {
        let (meta, gc_stream) = self.prepare_stream(file_callback)?;
        Ok(Box::new(NonCloneableStream::new(WiiDiscStream {
            meta: Arc::new(meta),
            gc_stream,
            pos: 0,
            cached_group: None,
        })))
    }

    fn prepare_stream<Cb>(self, file_callback: Cb) -> Result<(WiiDiscMeta, GCPartitionStream<Cb>)>
    where Cb: FileCallback {
        let Self { gc_writer, mut ticket, mut tmd, cert_chain, title_key, region } = self;
        let mut gc_stream = gc_writer.into_gc_stream(file_callback);
        let gc_data_size = gc_stream.len();
        let num_sectors =
            u32::try_from(gc_data_size.div_ceil(SECTOR_DATA_SIZE as u64)).map_err(|_| {
                Error::Other("GC partition is too large for a Wii partition".to_string())
            })?;
        let num_groups = num_sectors.div_ceil(64);
        if num_groups as usize * size_of::<[u8; 20]>() > H3_TABLE_SIZE {
            return Err(Error::Other("Partition H3 table exceeds Wii limits".to_string()));
        }

        let mut h3_table = vec![0u8; H3_TABLE_SIZE];
        let mut group_buf = vec![0u8; SECTOR_GROUP_SIZE];
        for group_idx in 0..num_groups {
            let base_sector = group_idx * 64;
            let sectors_in_group = (num_sectors.saturating_sub(base_sector) as usize).min(64);
            fill_group_plaintext_data(
                &mut gc_stream,
                gc_data_size,
                base_sector,
                sectors_in_group,
                &mut group_buf,
            )
            .with_context(|| format!("Building plaintext sector group {group_idx}"))?;
            // Zero groups (gap sectors between files) produce a zero H3 entry.
            // The TMD content hash is updated to match the full h3_table afterward.
            if group_buf.iter().any(|&b| b != 0) {
                let group_slice: &[u8; SECTOR_GROUP_SIZE] = group_buf
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Other("Sector group buffer size mismatch".to_string()))?;
                let hashes = hash_sector_group(group_slice, true);
                let h3_offset = group_idx as usize * 20;
                h3_table[h3_offset..h3_offset + 20].copy_from_slice(&hashes.h3_hash);
            }
        }

        let encrypted_data_size = num_sectors as u64 * SECTOR_SIZE as u64;
        zero_signature(&mut ticket);
        zero_signature(&mut tmd);
        update_tmd_content_hash(&mut tmd, encrypted_data_size, &h3_table)?;

        let outer_area = build_outer_area(&mut gc_stream, &region)?;
        let partition_header =
            build_partition_header(&ticket, &tmd, &cert_chain, &h3_table, encrypted_data_size)?;
        let disc_size = DATA_START + encrypted_data_size;
        Ok((
            WiiDiscMeta {
                outer_area: Arc::from(outer_area),
                partition_header: Arc::from(partition_header),
                title_key,
                num_sectors,
                disc_size,
            },
            gc_stream,
        ))
    }
}

impl<Cb: Clone> Clone for WiiDiscStream<Cb> {
    fn clone(&self) -> Self {
        Self {
            meta: Arc::clone(&self.meta),
            gc_stream: self.gc_stream.clone(),
            pos: 0,
            cached_group: None,
        }
    }
}

impl<Cb> WiiDiscStream<Cb>
where Cb: FileCallback
{
    fn compute_encrypted_group(&mut self, group_idx: u32) -> io::Result<Box<[u8]>> {
        let base_sector = group_idx * 64;
        let sectors_in_group = (self.meta.num_sectors.saturating_sub(base_sector) as usize).min(64);
        let mut group_buf = vec![0u8; SECTOR_GROUP_SIZE];
        let gc_data_size = self.gc_stream.len();

        fill_group_plaintext_data(
            &mut self.gc_stream,
            gc_data_size,
            base_sector,
            sectors_in_group,
            &mut group_buf,
        )?;

        if group_buf.iter().all(|&b| b == 0) {
            return Ok(group_buf.into_boxed_slice());
        }

        let hashes = {
            let sector_group: &[u8; SECTOR_GROUP_SIZE] = group_buf
                .as_slice()
                .try_into()
                .map_err(|_| io::Error::other("group buf size mismatch"))?;
            hash_sector_group(sector_group, true)
        };

        for sector_idx in 0..sectors_in_group {
            let start = sector_idx * SECTOR_SIZE;
            let end = start + SECTOR_SIZE;
            let sector: &mut [u8; SECTOR_SIZE] = (&mut group_buf[start..end])
                .try_into()
                .map_err(|_| io::Error::other("sector size mismatch"))?;
            hashes.apply(sector, sector_idx);
            encrypt_sector(sector, &self.meta.title_key);
        }

        Ok(group_buf.into_boxed_slice())
    }
}

impl<Cb> Read for WiiDiscStream<Cb>
where Cb: FileCallback
{
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let pos = self.pos;
        if pos >= self.meta.disc_size || out.is_empty() {
            return Ok(0);
        }

        let read_len = if pos < PARTITION_START {
            let available = (PARTITION_START - pos) as usize;
            let read_len = out.len().min(available);
            out[..read_len]
                .copy_from_slice(&self.meta.outer_area[pos as usize..pos as usize + read_len]);
            read_len
        } else if pos < DATA_START {
            let offset = (pos - PARTITION_START) as usize;
            let available = (DATA_START - pos) as usize;
            let read_len = out.len().min(available);
            out[..read_len].copy_from_slice(&self.meta.partition_header[offset..offset + read_len]);
            read_len
        } else {
            let data_offset = pos - DATA_START;
            let sector_idx = (data_offset / SECTOR_SIZE as u64) as u32;
            let within_sector = (data_offset % SECTOR_SIZE as u64) as usize;
            let group_idx = sector_idx / 64;

            if self.cached_group.as_ref().map(|(cached_group, _)| *cached_group) != Some(group_idx)
            {
                let group = self.compute_encrypted_group(group_idx)?;
                self.cached_group = Some((group_idx, group));
            }

            let group = match self.cached_group.as_ref() {
                Some((_, group)) => group,
                None => return Err(io::Error::other("missing Wii sector group cache")),
            };
            let sector_in_group = (sector_idx % 64) as usize;
            let sector_start = sector_in_group * SECTOR_SIZE;
            let source_start = sector_start + within_sector;
            let source_end = sector_start + SECTOR_SIZE;
            let read_len = out.len().min(source_end - source_start);
            out[..read_len].copy_from_slice(&group[source_start..source_start + read_len]);
            read_len
        };

        self.pos += read_len as u64;
        Ok(read_len)
    }
}

impl<Cb> Seek for WiiDiscStream<Cb> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self.meta.disc_size.saturating_add_signed(value),
            SeekFrom::Current(value) => self.pos.saturating_add_signed(value),
        };
        Ok(self.pos)
    }
}

fn fill_group_plaintext_data<Cb>(
    gc_stream: &mut GCPartitionStream<Cb>,
    gc_data_size: u64,
    base_sector: u32,
    sectors_in_group: usize,
    group_buf: &mut [u8],
) -> io::Result<()>
where
    Cb: FileCallback,
{
    group_buf.fill(0);
    let group_offset = base_sector as u64 * SECTOR_DATA_SIZE as u64;
    gc_stream.seek(SeekFrom::Start(group_offset))?;
    let mut remaining = gc_data_size.saturating_sub(group_offset);
    for sector_idx in 0..sectors_in_group {
        let start = sector_idx * SECTOR_SIZE + HASHES_SIZE;
        let end = start + SECTOR_DATA_SIZE;
        let read_len = remaining.min(SECTOR_DATA_SIZE as u64) as usize;
        if read_len != 0 {
            gc_stream.read_exact(&mut group_buf[start..start + read_len])?;
            remaining -= read_len as u64;
        }
        if read_len < SECTOR_DATA_SIZE {
            group_buf[start + read_len..end].fill(0);
        }
    }
    Ok(())
}

fn build_outer_area<Cb>(
    gc_stream: &mut GCPartitionStream<Cb>,
    region: &Option<[u8; REGION_SIZE]>,
) -> Result<Vec<u8>>
where
    Cb: FileCallback,
{
    let mut outer = vec![0u8; PARTITION_START as usize];
    gc_stream.seek(SeekFrom::Start(0)).context("Seeking to GC boot data")?;
    gc_stream.read_exact(&mut outer[..BOOT_SIZE]).context("Reading GC boot data")?;

    write_u32_be(&mut outer, 0x40000, 1);
    write_u32_be(&mut outer, 0x40004, u32_from_offset_words(PARTITION_ENTRY_OFFSET)?);
    write_u32_be(
        &mut outer,
        PARTITION_ENTRY_OFFSET as usize,
        u32_from_offset_words(PARTITION_START)?,
    );
    write_u32_be(&mut outer, PARTITION_ENTRY_OFFSET as usize + 4, DATA_PART_KIND);
    if let Some(region_bytes) = region {
        outer[REGION_OFFSET as usize..REGION_OFFSET as usize + REGION_SIZE]
            .copy_from_slice(region_bytes);
    }
    Ok(outer)
}

fn build_partition_header(
    ticket: &[u8],
    tmd: &[u8],
    cert_chain: &[u8],
    h3_table: &[u8],
    encrypted_data_size: u64,
) -> Result<Vec<u8>> {
    if h3_table.len() != H3_TABLE_SIZE {
        return Err(Error::Other("Invalid H3 table size".to_string()));
    }

    let cert_offset = align_up(TMD_PART_OFFSET + tmd.len() as u64, 0x40);
    let cert_end = cert_offset + cert_chain.len() as u64;
    if cert_end > H3_TABLE_PART_OFFSET {
        return Err(Error::Other("TMD and cert chain overlap the H3 table".to_string()));
    }

    let mut partition_header = vec![0u8; DATA_PART_OFFSET as usize];
    let ticket_len = ticket.len().min(size_of::<Ticket>());
    partition_header[..ticket_len].copy_from_slice(&ticket[..ticket_len]);

    let tmd_offset = TMD_PART_OFFSET as usize;
    let tmd_end = tmd_offset + tmd.len();
    if tmd_end > partition_header.len() {
        return Err(Error::Other("TMD exceeds partition header area".to_string()));
    }
    partition_header[tmd_offset..tmd_end].copy_from_slice(tmd);

    let cert_offset_usize = cert_offset as usize;
    let cert_end_usize = cert_offset_usize + cert_chain.len();
    partition_header[cert_offset_usize..cert_end_usize].copy_from_slice(cert_chain);

    let h3_offset = H3_TABLE_PART_OFFSET as usize;
    partition_header[h3_offset..h3_offset + H3_TABLE_SIZE].copy_from_slice(h3_table);

    let info_offset = size_of::<Ticket>();
    write_u32_be(&mut partition_header, info_offset, u32_from_len(tmd.len())?);
    write_u32_be(&mut partition_header, info_offset + 4, u32_from_offset_words(TMD_PART_OFFSET)?);
    write_u32_be(&mut partition_header, info_offset + 8, u32_from_len(cert_chain.len())?);
    write_u32_be(&mut partition_header, info_offset + 12, u32_from_offset_words(cert_offset)?);
    write_u32_be(
        &mut partition_header,
        info_offset + 16,
        u32_from_offset_words(H3_TABLE_PART_OFFSET)?,
    );
    write_u32_be(&mut partition_header, info_offset + 20, u32_from_offset_words(DATA_PART_OFFSET)?);
    write_u32_be(
        &mut partition_header,
        info_offset + 24,
        u32_from_offset_words(encrypted_data_size)?,
    );

    Ok(partition_header)
}

fn zero_signature(blob: &mut Vec<u8>) {
    if blob.len() >= 0x104 {
        blob[0x004..0x104].fill(0);
    }
}

fn update_tmd_content_hash(
    tmd: &mut Vec<u8>,
    encrypted_data_size: u64,
    h3_table: &[u8],
) -> Result<()> {
    const SIZE_OFFSET: usize = 0x1EC;
    const HASH_OFFSET: usize = 0x1F4;

    if tmd.len() < HASH_OFFSET + 20 {
        return Err(Error::Other("TMD is too small to contain content metadata".to_string()));
    }

    tmd[SIZE_OFFSET..SIZE_OFFSET + 8].copy_from_slice(&encrypted_data_size.to_be_bytes());
    tmd[HASH_OFFSET..HASH_OFFSET + 20].copy_from_slice(&sha1_hash(h3_table));
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 { value } else { value.div_ceil(alignment) * alignment }
}

fn write_u32_be(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn u32_from_offset_words(offset: u64) -> Result<u32> {
    if offset % 4 != 0 {
        return Err(Error::Other(format!("Offset {offset:#X} is not 4-byte aligned")));
    }
    u32::try_from(offset / 4)
        .map_err(|_| Error::Other(format!("Offset {offset:#X} does not fit in Wii header")))
}

fn u32_from_len(len: usize) -> Result<u32> {
    u32::try_from(len)
        .map_err(|_| Error::Other(format!("Length {len:#X} does not fit in Wii header")))
}
