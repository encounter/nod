use std::{
    fs::File,
    io::{BufReader, Cursor, Write},
    mem::size_of,
    path::Path,
    str,
    sync::OnceLock,
};

use hex::deserialize as deserialize_hex;
use nod::Result;
use serde::Deserialize;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::util::array_ref;

#[derive(Clone, Debug)]
pub struct GameResult<'a> {
    pub name: &'a str,
    pub crc32: u32,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
}

pub struct EntryIter<'a> {
    data: &'a [u8],
    index: usize,
}

impl EntryIter<'static> {
    pub fn new() -> EntryIter<'static> {
        Self { data: loaded_data(), index: 0 }
    }
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = GameResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (header, remaining) = Header::ref_from_prefix(self.data).ok()?;
        assert_eq!(header.entry_size as usize, size_of::<GameEntry>());
        if self.index >= header.entry_count as usize {
            return None;
        }

        let entries_size = header.entry_count as usize * size_of::<GameEntry>();
        let entries = <[GameEntry]>::ref_from_bytes(&remaining[..entries_size]).ok()?;
        let string_table = &self.data[size_of::<Header>() + entries_size..];

        let entry = &entries[self.index];
        let offset = entry.string_table_offset as usize;
        let name_size = u32::from_ne_bytes(*array_ref![string_table, offset, 4]) as usize;
        let name = str::from_utf8(&string_table[offset + 4..offset + 4 + name_size]).unwrap();
        self.index += 1;
        Some(GameResult { name, crc32: entry.crc32, md5: entry.md5, sha1: entry.sha1 })
    }
}

pub fn find_by_crc32(crc32: u32) -> Option<GameResult<'static>> {
    let data = loaded_data();
    let (header, remaining) = Header::ref_from_prefix(data).ok()?;
    assert_eq!(header.entry_size as usize, size_of::<GameEntry>());

    let entries_size = header.entry_count as usize * size_of::<GameEntry>();
    let (entries_buf, string_table) = remaining.split_at(entries_size);
    let entries = <[GameEntry]>::ref_from_bytes(entries_buf).ok()?;

    // Binary search by CRC32
    let index = entries.binary_search_by_key(&crc32, |entry| entry.crc32).ok()?;

    // Parse the entry
    let entry = &entries[index];
    let offset = entry.string_table_offset as usize;
    let name_size = u32::from_ne_bytes(*array_ref![string_table, offset, 4]) as usize;
    let name = str::from_utf8(&string_table[offset + 4..offset + 4 + name_size]).unwrap();
    Some(GameResult { name, crc32: entry.crc32, md5: entry.md5, sha1: entry.sha1 })
}

const BUILTIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/parsed-dats.bin"));
static LOADED: OnceLock<Box<[u8]>> = OnceLock::new();

fn loaded_data() -> &'static [u8] {
    LOADED
        .get_or_init(|| {
            let size = zstd::zstd_safe::get_frame_content_size(BUILTIN).unwrap().unwrap() as usize;
            let mut out = <[u8]>::new_box_zeroed_with_elems(size).unwrap();
            let out_size = zstd::bulk::Decompressor::new()
                .unwrap()
                .decompress_to_buffer(BUILTIN, out.as_mut())
                .unwrap();
            debug_assert_eq!(out_size, size);
            out
        })
        .as_ref()
}

pub fn load_dats<'a>(paths: impl Iterator<Item = &'a Path>) -> Result<()> {
    // Parse dat files
    let mut entries = Vec::<(GameEntry, String)>::new();
    for path in paths {
        let file = BufReader::new(File::open(path).expect("Failed to open dat file"));
        let dat: DatFile = quick_xml::de::from_reader(file).expect("Failed to parse dat file");
        entries.extend(dat.games.into_iter().filter_map(|game| {
            if game.roms.len() != 1 {
                return None;
            }
            let rom = &game.roms[0];
            Some((
                GameEntry {
                    string_table_offset: 0,
                    crc32: u32::from_be_bytes(rom.crc32),
                    md5: rom.md5,
                    sha1: rom.sha1,
                    sectors: rom.size.div_ceil(0x8000) as u32,
                },
                game.name,
            ))
        }));
    }

    // Sort by CRC32
    entries.sort_by_key(|(entry, _)| entry.crc32);

    // Calculate total size
    let entries_size = entries.len() * size_of::<GameEntry>();
    let string_table_size = entries.iter().map(|(_, name)| name.len() + 4).sum::<usize>();
    let total_size = size_of::<Header>() + entries_size + string_table_size;
    let mut result = <[u8]>::new_box_zeroed_with_elems(total_size)?;
    let mut out = Cursor::new(result.as_mut());

    // Write game entries
    let header =
        Header { entry_count: entries.len() as u32, entry_size: size_of::<GameEntry>() as u32 };
    out.write_all(header.as_bytes()).unwrap();
    let mut string_table_offset = 0u32;
    for (entry, name) in &mut entries {
        entry.string_table_offset = string_table_offset;
        out.write_all(entry.as_bytes()).unwrap();
        string_table_offset += name.len() as u32 + 4;
    }

    // Write string table
    for (_, name) in &entries {
        out.write_all(&(name.len() as u32).to_le_bytes()).unwrap();
        out.write_all(name.as_bytes()).unwrap();
    }

    // Finalize
    assert_eq!(out.position() as usize, total_size);
    LOADED.set(result).map_err(|_| nod::Error::Other("dats already loaded".to_string()))
}

// Keep in sync with build.rs
#[derive(Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
struct Header {
    entry_count: u32,
    entry_size: u32,
}

// Keep in sync with build.rs
#[derive(Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
struct GameEntry {
    crc32: u32,
    string_table_offset: u32,
    sectors: u32,
    md5: [u8; 16],
    sha1: [u8; 20],
}

#[derive(Clone, Debug, Deserialize)]
struct DatFile {
    #[serde(rename = "game")]
    games: Vec<DatGame>,
}

#[derive(Clone, Debug, Deserialize)]
struct DatGame {
    #[serde(rename = "@name")]
    name: String,
    // #[serde(rename = "category", default)]
    // categories: Vec<String>,
    #[serde(rename = "rom")]
    roms: Vec<DatGameRom>,
}

#[derive(Clone, Debug, Deserialize)]
struct DatGameRom {
    // #[serde(rename = "@name")]
    // name: String,
    #[serde(rename = "@size")]
    size: u64,
    #[serde(rename = "@crc", deserialize_with = "deserialize_hex")]
    crc32: [u8; 4],
    #[serde(rename = "@md5", deserialize_with = "deserialize_hex")]
    md5: [u8; 16],
    #[serde(rename = "@sha1", deserialize_with = "deserialize_hex")]
    sha1: [u8; 20],
}
