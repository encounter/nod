use std::io::Read as IoRead;
use std::sync::{Arc, Mutex};

use crate::common::PartitionKind as NodPartitionKind;
use crate::disc::DiscHeader as NodDiscHeader;
use crate::disc::fst::Node;
use crate::read::{
    DiscMeta as NodDiscMeta, DiscOptions, DiscReader as NodDiscReader, PartitionMeta,
    PartitionOptions, PartitionReader,
};
use pyo3::exceptions::{PyIOError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn nod_err(e: crate::Error) -> PyErr {
    use pyo3::exceptions::PyFileNotFoundError;
    use std::io::ErrorKind;
    match &e {
        crate::Error::Io(_, io_err) if io_err.kind() == ErrorKind::NotFound => {
            PyFileNotFoundError::new_err(format!("{e}"))
        }
        _ => PyIOError::new_err(format!("{e}")),
    }
}

fn io_err(e: std::io::Error) -> PyErr {
    PyIOError::new_err(format!("{e}"))
}

// ---------------------------------------------------------------------------
// DiscHeader
// ---------------------------------------------------------------------------

#[pyclass(name = "DiscHeader", frozen)]
pub struct PyDiscHeader {
    #[pyo3(get)]
    pub game_id: String,
    #[pyo3(get)]
    pub game_title: String,
    #[pyo3(get)]
    pub disc_num: u8,
    #[pyo3(get)]
    pub disc_version: u8,
    #[pyo3(get)]
    pub audio_streaming: u8,
    #[pyo3(get)]
    pub audio_stream_buf_size: u8,
    #[pyo3(get)]
    pub is_wii: bool,
    #[pyo3(get)]
    pub is_gamecube: bool,
}

#[pymethods]
impl PyDiscHeader {
    fn __repr__(&self) -> String {
        format!(
            "DiscHeader(game_id={:?}, game_title={:?}, is_wii={})",
            self.game_id, self.game_title, self.is_wii
        )
    }
}

fn from_disc_header(h: &NodDiscHeader) -> PyDiscHeader {
    PyDiscHeader {
        game_id: h.game_id_str().to_string(),
        game_title: h.game_title_str().to_string(),
        disc_num: h.disc_num,
        disc_version: h.disc_version,
        audio_streaming: h.audio_streaming,
        audio_stream_buf_size: h.audio_stream_buf_size,
        is_wii: h.is_wii(),
        is_gamecube: h.is_gamecube(),
    }
}

// ---------------------------------------------------------------------------
// DiscMeta
// ---------------------------------------------------------------------------

#[pyclass(name = "DiscMeta", frozen)]
pub struct PyDiscMeta {
    #[pyo3(get)]
    pub format: String,
    #[pyo3(get)]
    pub compression: String,
    #[pyo3(get)]
    pub block_size: Option<u32>,
    #[pyo3(get)]
    pub decrypted: bool,
    #[pyo3(get)]
    pub needs_hash_recovery: bool,
    #[pyo3(get)]
    pub lossless: bool,
    #[pyo3(get)]
    pub disc_size: Option<u64>,
    #[pyo3(get)]
    pub crc32: Option<u32>,
    #[pyo3(get)]
    pub xxh64: Option<u64>,
}

#[pymethods]
impl PyDiscMeta {
    fn __repr__(&self) -> String {
        format!("DiscMeta(format={:?}, compression={:?})", self.format, self.compression)
    }
}

fn from_disc_meta(m: &NodDiscMeta) -> PyDiscMeta {
    PyDiscMeta {
        format: m.format.to_string(),
        compression: m.compression.to_string(),
        block_size: m.block_size,
        decrypted: m.decrypted,
        needs_hash_recovery: m.needs_hash_recovery,
        lossless: m.lossless,
        disc_size: m.disc_size,
        crc32: m.crc32,
        xxh64: m.xxh64,
    }
}

// ---------------------------------------------------------------------------
// PartitionInfo
// ---------------------------------------------------------------------------

#[pyclass(name = "PartitionInfo", frozen)]
pub struct PyPartitionInfo {
    #[pyo3(get)]
    pub index: usize,
    #[pyo3(get)]
    pub kind: String,
}

#[pymethods]
impl PyPartitionInfo {
    fn __repr__(&self) -> String {
        format!("PartitionInfo(index={}, kind={:?})", self.index, self.kind)
    }
}

// ---------------------------------------------------------------------------
// FstNode
// ---------------------------------------------------------------------------

/// A single file system entry. Returned by [`Fst.find`] and [`Fst.__iter__`].
/// Pass to [`PartitionReader.read_file`] to read the file contents.
#[pyclass(name = "FstNode", frozen)]
#[derive(Clone)]
pub struct PyFstNode {
    /// The name component of this entry (last path segment).
    #[pyo3(get)]
    pub name: String,
    /// The full path from the partition root, using `/` as separator.
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub is_file: bool,
    #[pyo3(get)]
    pub is_dir: bool,
    /// For files: the byte size of the file.
    /// For directories: the child-end index in the FST.
    #[pyo3(get)]
    pub length: u32,
    /// Index of this node in the FST array.
    #[pyo3(get)]
    pub fst_index: usize,
    // Kept internal; used by PartitionReader.read_file.
    pub(crate) node: Node,
}

#[pymethods]
impl PyFstNode {
    fn __repr__(&self) -> String {
        if self.is_file {
            format!("FstNode(path={:?}, length={})", self.path, self.length)
        } else {
            format!("FstNode(path={:?}, dir=True)", self.path)
        }
    }
}

// ---------------------------------------------------------------------------
// FstIter
// ---------------------------------------------------------------------------

#[pyclass(name = "FstIter")]
pub struct PyFstIter {
    entries: Vec<PyFstNode>,
    index: usize,
}

#[pymethods]
impl PyFstIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<PyFstNode> {
        if self.index < self.entries.len() {
            let entry = self.entries[self.index].clone();
            self.index += 1;
            Some(entry)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Fst
// ---------------------------------------------------------------------------

#[pyclass(name = "Fst")]
pub struct PyFst {
    raw_fst: Arc<[u8]>,
}

#[pymethods]
impl PyFst {
    /// Find a file or directory by its path (case-insensitive).
    /// Returns `None` if not found.
    fn find(&self, path: &str) -> PyResult<Option<PyFstNode>> {
        let buf: &[u8] = &self.raw_fst;
        let fst = crate::disc::fst::Fst::new(buf)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid FST: {e}")))?;
        Ok(fst.find(path).map(|(idx, node)| {
            let name = fst.get_name(node).unwrap_or_default().into_owned();
            PyFstNode {
                name,
                path: path.trim_matches('/').to_string(),
                is_file: node.is_file(),
                is_dir: node.is_dir(),
                length: node.length(),
                fst_index: idx,
                node,
            }
        }))
    }

    fn __iter__(&self) -> PyResult<PyFstIter> {
        let buf: &[u8] = &self.raw_fst;
        let fst = crate::disc::fst::Fst::new(buf)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid FST: {e}")))?;
        let entries: Vec<PyFstNode> = fst
            .iter()
            .map(|(idx, node, path)| {
                let name = fst.get_name(node).unwrap_or_default().into_owned();
                PyFstNode {
                    name,
                    path,
                    is_file: node.is_file(),
                    is_dir: node.is_dir(),
                    length: node.length(),
                    fst_index: idx,
                    node,
                }
            })
            .collect();
        Ok(PyFstIter { entries, index: 0 })
    }

    fn __repr__(&self) -> String {
        "Fst(...)".to_string()
    }
}

// ---------------------------------------------------------------------------
// PartitionMeta
// ---------------------------------------------------------------------------

#[pyclass(name = "PartitionMeta")]
pub struct PyPartitionMeta {
    inner: Arc<PartitionMeta>,
}

#[pymethods]
impl PyPartitionMeta {
    /// Returns the file system table.
    fn fst(&self) -> PyResult<PyFst> {
        Ok(PyFst { raw_fst: Arc::clone(&self.inner.raw_fst) })
    }

    /// Disc and boot header (boot.bin, 0x440 bytes).
    #[getter]
    fn raw_boot<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.raw_boot.as_ref())
    }

    /// Debug and region information (bi2.bin, 0x2000 bytes).
    #[getter]
    fn raw_bi2<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.raw_bi2.as_ref())
    }

    /// Apploader binary (apploader.bin).
    #[getter]
    fn raw_apploader<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.raw_apploader)
    }

    /// Main executable binary (main.dol).
    #[getter]
    fn raw_dol<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.raw_dol)
    }

    /// Raw file system table (fst.bin).
    #[getter]
    fn raw_fst<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.raw_fst)
    }

    /// Wii ticket (ticket.bin), or `None` for GameCube discs.
    #[getter]
    fn raw_ticket<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.raw_ticket.as_deref().map(|b| PyBytes::new(py, b))
    }

    /// Wii title metadata (tmd.bin), or `None` for GameCube discs.
    #[getter]
    fn raw_tmd<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.raw_tmd.as_deref().map(|b| PyBytes::new(py, b))
    }

    /// Wii certificate chain (cert.bin), or `None` for GameCube discs.
    #[getter]
    fn raw_cert_chain<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.raw_cert_chain.as_deref().map(|b| PyBytes::new(py, b))
    }

    /// Wii H3 hash table (h3.bin), or `None` for GameCube discs.
    #[getter]
    fn raw_h3_table<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.raw_h3_table.as_deref().map(|b| PyBytes::new(py, b.as_ref()))
    }

    /// Disc header information parsed from boot.bin.
    fn disc_header(&self) -> PyDiscHeader {
        from_disc_header(self.inner.disc_header())
    }

    fn __repr__(&self) -> String {
        "PartitionMeta(...)".to_string()
    }
}

// ---------------------------------------------------------------------------
// PartitionReader
// ---------------------------------------------------------------------------

#[pyclass(name = "PartitionReader")]
pub struct PyPartitionReader {
    inner: Arc<Mutex<Box<dyn PartitionReader>>>,
}

#[pymethods]
impl PyPartitionReader {
    /// Returns `True` for Wii partitions, `False` for GameCube.
    fn is_wii(&self) -> bool {
        self.inner.lock().unwrap().is_wii()
    }

    /// Reads the partition header and file system metadata.
    fn meta(&self) -> PyResult<PyPartitionMeta> {
        let meta = self.inner.lock().unwrap().meta().map_err(nod_err)?;
        Ok(PyPartitionMeta { inner: Arc::new(meta) })
    }

    /// Reads the contents of a file specified by a [`FstNode`].
    /// Returns the file data as `bytes`.
    fn read_file<'py>(&self, py: Python<'py>, node: &PyFstNode) -> PyResult<Bound<'py, PyBytes>> {
        if !node.is_file {
            return Err(pyo3::exceptions::PyIsADirectoryError::new_err(format!(
                "{:?} is a directory",
                node.path
            )));
        }
        let mut guard = self.inner.lock().unwrap();
        let mut file = guard.open_file(node.node).map_err(io_err)?;
        let size = node.length as usize;
        let mut buf = Vec::with_capacity(size);
        file.read_to_end(&mut buf).map_err(io_err)?;
        Ok(PyBytes::new(py, &buf))
    }

    fn __repr__(&self) -> String {
        let is_wii = self.inner.lock().unwrap().is_wii();
        format!("PartitionReader(is_wii={})", is_wii)
    }
}

// ---------------------------------------------------------------------------
// DiscReader
// ---------------------------------------------------------------------------

#[pyclass(name = "DiscReader")]
pub struct PyDiscReader {
    inner: Arc<Mutex<NodDiscReader>>,
}

#[pymethods]
impl PyDiscReader {
    /// Returns the disc's primary header.
    fn header(&self) -> PyDiscHeader {
        let guard = self.inner.lock().unwrap();
        from_disc_header(guard.header())
    }

    /// Returns extra metadata about the underlying disc file format.
    fn meta(&self) -> PyDiscMeta {
        let guard = self.inner.lock().unwrap();
        from_disc_meta(&guard.meta())
    }

    /// Returns the disc's size in bytes.
    fn disc_size(&self) -> u64 {
        self.inner.lock().unwrap().disc_size()
    }

    /// Returns a list of Wii partitions. Empty for GameCube discs.
    fn partitions(&self) -> Vec<PyPartitionInfo> {
        let guard = self.inner.lock().unwrap();
        guard
            .partitions()
            .iter()
            .map(|p| PyPartitionInfo {
                index: p.index,
                kind: p.kind.to_string(),
            })
            .collect()
    }

    /// Opens a partition by index.
    /// For GameCube discs, `index` must be 0.
    #[pyo3(signature = (index, validate_hashes=false))]
    fn open_partition(
        &self,
        index: usize,
        validate_hashes: bool,
    ) -> PyResult<PyPartitionReader> {
        let options = PartitionOptions { validate_hashes };
        let reader = self.inner.lock().unwrap().open_partition(index, &options).map_err(nod_err)?;
        Ok(PyPartitionReader { inner: Arc::new(Mutex::new(reader)) })
    }

    /// Opens the first partition matching `kind`.
    /// `kind` is a string: `"Data"`, `"Update"`, `"Channel"`.
    /// For GameCube discs, use `"Data"`.
    #[pyo3(signature = (kind="Data", validate_hashes=false))]
    fn open_partition_kind(
        &self,
        kind: &str,
        validate_hashes: bool,
    ) -> PyResult<PyPartitionReader> {
        let partition_kind = match kind {
            "Data" => NodPartitionKind::Data,
            "Update" => NodPartitionKind::Update,
            "Channel" => NodPartitionKind::Channel,
            other => {
                return Err(PyValueError::new_err(format!(
                    "Unknown partition kind {:?}. Expected \"Data\", \"Update\", or \"Channel\".",
                    other
                )));
            }
        };
        let options = PartitionOptions { validate_hashes };
        let reader = self
            .inner
            .lock()
            .unwrap()
            .open_partition_kind(partition_kind, &options)
            .map_err(nod_err)?;
        Ok(PyPartitionReader { inner: Arc::new(Mutex::new(reader)) })
    }

    fn __repr__(&self) -> String {
        let guard = self.inner.lock().unwrap();
        let h = guard.header();
        format!(
            "DiscReader(game_id={:?}, game_title={:?})",
            h.game_id_str(),
            h.game_title_str()
        )
    }
}

// ---------------------------------------------------------------------------
// Module-level open() function
// ---------------------------------------------------------------------------

/// Open a disc image from the given file path.
///
/// Supports ISO, CISO, GCZ, NFS, RVZ, WBFS, WIA, and TGC formats.
///
/// Example::
///
///     import nod
///     disc = nod.open("game.iso")
///     header = disc.header()
///     print(header.game_id, header.game_title)
///     partition = disc.open_partition_kind("Data")
///     meta = partition.meta()
///     fst = meta.fst()
///     node = fst.find("/MP3/Worlds.txt")
///     if node:
///         data = partition.read_file(node)
#[pyfunction]
fn open(path: &str) -> PyResult<PyDiscReader> {
    let reader = NodDiscReader::new(path, &DiscOptions::default()).map_err(nod_err)?;
    Ok(PyDiscReader { inner: Arc::new(Mutex::new(reader)) })
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(open, m)?)?;
    m.add_class::<PyDiscReader>()?;
    m.add_class::<PyDiscHeader>()?;
    m.add_class::<PyDiscMeta>()?;
    m.add_class::<PyPartitionInfo>()?;
    m.add_class::<PyPartitionReader>()?;
    m.add_class::<PyPartitionMeta>()?;
    m.add_class::<PyFst>()?;
    m.add_class::<PyFstNode>()?;
    m.add_class::<PyFstIter>()?;
    Ok(())
}
