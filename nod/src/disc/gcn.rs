use std::{
    io,
    io::{BufRead, Read, Seek, SeekFrom},
    mem::size_of,
    sync::Arc,
};

use zerocopy::FromBytes;

use crate::{
    disc::{
        preloader::{fetch_sector_group, Preloader, SectorGroup, SectorGroupRequest},
        ApploaderHeader, DiscHeader, DolHeader, PartitionHeader, BI2_SIZE, BOOT_SIZE,
        SECTOR_GROUP_SIZE, SECTOR_SIZE,
    },
    io::block::BlockReader,
    read::{PartitionEncryption, PartitionMeta, PartitionReader},
    util::{
        impl_read_for_bufread,
        read::{read_arc, read_arc_slice, read_vec},
    },
    Result, ResultContext,
};

pub struct PartitionReaderGC {
    io: Box<dyn BlockReader>,
    preloader: Arc<Preloader>,
    pos: u64,
    disc_size: u64,
    sector_group: Option<SectorGroup>,
    meta: Option<PartitionMeta>,
}

impl Clone for PartitionReaderGC {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            preloader: self.preloader.clone(),
            pos: 0,
            disc_size: self.disc_size,
            sector_group: None,
            meta: self.meta.clone(),
        }
    }
}

impl PartitionReaderGC {
    pub fn new(
        inner: Box<dyn BlockReader>,
        preloader: Arc<Preloader>,
        disc_size: u64,
    ) -> Result<Box<Self>> {
        Ok(Box::new(Self {
            io: inner,
            preloader,
            pos: 0,
            disc_size,
            sector_group: None,
            meta: None,
        }))
    }
}

impl BufRead for PartitionReaderGC {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.disc_size {
            return Ok(&[]);
        }

        let abs_sector = (self.pos / SECTOR_SIZE as u64) as u32;
        let group_idx = abs_sector / 64;
        let abs_group_sector = group_idx * 64;
        let max_groups = self.disc_size.div_ceil(SECTOR_GROUP_SIZE as u64) as u32;
        let request = SectorGroupRequest {
            group_idx,
            partition_idx: None,
            mode: PartitionEncryption::Original,
        };

        // Load sector group
        let (sector_group, _updated) =
            fetch_sector_group(request, max_groups, &mut self.sector_group, &self.preloader)?;

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
        let end =
            (num_sectors as u64 * SECTOR_SIZE as u64).min(self.disc_size - group_start) as usize;
        Ok(&sector_group.data[offset..end])
    }

    #[inline]
    fn consume(&mut self, amt: usize) { self.pos += amt as u64; }
}

impl_read_for_bufread!(PartitionReaderGC);

impl Seek for PartitionReaderGC {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => self.disc_size.saturating_add_signed(v),
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };
        Ok(self.pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos) }
}

impl PartitionReader for PartitionReaderGC {
    fn is_wii(&self) -> bool { false }

    fn meta(&mut self) -> Result<PartitionMeta> {
        if let Some(meta) = &self.meta {
            Ok(meta.clone())
        } else {
            let meta = read_part_meta(self, false)?;
            self.meta = Some(meta.clone());
            Ok(meta)
        }
    }
}

pub(crate) fn read_dol(
    reader: &mut dyn PartitionReader,
    partition_header: &PartitionHeader,
    is_wii: bool,
) -> Result<Arc<[u8]>> {
    reader
        .seek(SeekFrom::Start(partition_header.dol_offset(is_wii)))
        .context("Seeking to DOL offset")?;
    let mut raw_dol: Vec<u8> =
        read_vec(reader, size_of::<DolHeader>()).context("Reading DOL header")?;
    let dol_header = DolHeader::ref_from_bytes(raw_dol.as_slice()).unwrap();
    let dol_size = (dol_header.text_offs.iter().zip(&dol_header.text_sizes))
        .chain(dol_header.data_offs.iter().zip(&dol_header.data_sizes))
        .map(|(offs, size)| offs.get() + size.get())
        .max()
        .unwrap_or(size_of::<DolHeader>() as u32);
    raw_dol.resize(dol_size as usize, 0);
    reader.read_exact(&mut raw_dol[size_of::<DolHeader>()..]).context("Reading DOL")?;
    Ok(Arc::from(raw_dol.as_slice()))
}

pub(crate) fn read_fst<R>(
    reader: &mut R,
    partition_header: &PartitionHeader,
    is_wii: bool,
) -> Result<Arc<[u8]>>
where
    R: Read + Seek + ?Sized,
{
    reader
        .seek(SeekFrom::Start(partition_header.fst_offset(is_wii)))
        .context("Seeking to FST offset")?;
    let raw_fst: Arc<[u8]> = read_arc_slice(reader, partition_header.fst_size(is_wii) as usize)
        .with_context(|| {
            format!(
                "Reading partition FST (offset {}, size {})",
                partition_header.fst_offset(is_wii),
                partition_header.fst_size(is_wii)
            )
        })?;
    Ok(raw_fst)
}

pub(crate) fn read_part_meta(
    reader: &mut dyn PartitionReader,
    is_wii: bool,
) -> Result<PartitionMeta> {
    // boot.bin
    let raw_boot: Arc<[u8; BOOT_SIZE]> = read_arc(reader).context("Reading boot.bin")?;
    let partition_header =
        PartitionHeader::ref_from_bytes(&raw_boot[size_of::<DiscHeader>()..]).unwrap();

    // bi2.bin
    let raw_bi2: Arc<[u8; BI2_SIZE]> = read_arc(reader).context("Reading bi2.bin")?;

    // apploader.bin
    let mut raw_apploader: Vec<u8> =
        read_vec(reader, size_of::<ApploaderHeader>()).context("Reading apploader header")?;
    let apploader_header = ApploaderHeader::ref_from_bytes(raw_apploader.as_slice()).unwrap();
    let apploader_size = size_of::<ApploaderHeader>()
        + apploader_header.size.get() as usize
        + apploader_header.trailer_size.get() as usize;
    raw_apploader.resize(apploader_size, 0);
    reader
        .read_exact(&mut raw_apploader[size_of::<ApploaderHeader>()..])
        .context("Reading apploader")?;
    let raw_apploader = Arc::from(raw_apploader.as_slice());

    // fst.bin
    let raw_fst = read_fst(reader, partition_header, is_wii)?;

    // main.dol
    let raw_dol = read_dol(reader, partition_header, is_wii)?;

    Ok(PartitionMeta {
        raw_boot,
        raw_bi2,
        raw_apploader,
        raw_fst,
        raw_dol,
        raw_ticket: None,
        raw_tmd: None,
        raw_cert_chain: None,
        raw_h3_table: None,
    })
}
