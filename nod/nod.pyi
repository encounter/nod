from __future__ import annotations

from collections.abc import Callable
from types import TracebackType

class DiscHeader:
    """Primary disc header (boot.bin offset 0x000)."""

    game_id: str
    """Six-character game ID, e.g. ``"GM8E01"``."""
    game_title: str
    """Game title string, e.g. ``"Metroid Prime"``."""
    disc_num: int
    """Disc number (0-based)."""
    disc_version: int
    """Disc revision number."""
    audio_streaming: int
    audio_stream_buf_size: int
    is_wii: bool
    """``True`` for Wii discs."""
    is_gamecube: bool
    """``True`` for GameCube discs."""

    def __repr__(self) -> str: ...

class DiscMeta:
    """Extra metadata supplied by the disc file format (not the disc itself)."""

    format: str
    """File format name: ``"ISO"``, ``"CISO"``, ``"GCZ"``, ``"NFS"``, ``"RVZ"``,
    ``"WBFS"``, ``"WIA"``, or ``"TGC"``."""
    compression: str
    """Compression algorithm description, e.g. ``"Zstandard (19)"`` or ``"None"``."""
    block_size: int | None
    """Block size in bytes for block-based formats, ``None`` otherwise."""
    decrypted: bool
    """Whether Wii partition data is stored decrypted in this format."""
    needs_hash_recovery: bool
    """Whether Wii partition hashes are omitted and need to be rebuilt."""
    lossless: bool
    """Whether the original disc data can be recovered without loss."""
    disc_size: int | None
    """Original disc size in bytes if stored by the format, ``None`` otherwise."""
    crc32: int | None
    """CRC-32 checksum of the original disc, if stored by the format."""
    xxh64: int | None
    """XXH64 checksum of the original disc, if stored by the format."""

    def __repr__(self) -> str: ...

class PartitionInfo:
    """Describes a single Wii partition (not present on GameCube discs)."""

    index: int
    """Zero-based partition index."""
    kind: str
    """Partition kind: ``"Data"``, ``"Update"``, ``"Channel"``, or ``"Other (…)"``."""

    def __repr__(self) -> str: ...

class FileReader:
    """Lazy, seekable binary file reader backed by a disc partition.

    Returned by :meth:`PartitionReader.read_file`. Data is read from the
    source disc on demand — nothing is buffered until you call :meth:`read`.

    Implements the standard binary-IO interface and can be used as a context
    manager::

        with partition.read_file(node) as f:
            header = f.read(4)
            f.seek(0)
            all_data = f.read()
    """

    def read(self, size: int = -1) -> bytes:
        """Read and return up to *size* bytes.

        If *size* is ``-1`` (default), reads until end of file.
        """

    def seek(self, pos: int, whence: int = 0) -> int:
        """Seek to *pos* bytes relative to *whence*.

        *whence*: ``0`` = start (default), ``1`` = current position,
        ``2`` = end of file. Returns the new absolute position.
        """

    def tell(self) -> int:
        """Return the current stream position."""

    def size(self) -> int:
        """Return the total file size in bytes."""

    def readable(self) -> bool: ...
    def seekable(self) -> bool: ...
    def writable(self) -> bool: ...

    @property
    def closed(self) -> bool: ...
    def close(self) -> None: ...

    def __enter__(self) -> FileReader: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
    def __repr__(self) -> str: ...

class FstNode:
    """A single entry in the file system table.

    Returned by :meth:`Fst.find` and iteration over :class:`Fst`.
    Pass to :meth:`PartitionReader.read_file` to read file contents.
    """

    name: str
    """Filename component (last path segment)."""
    path: str
    """Full path from the partition root, segments separated by ``/``."""
    is_file: bool
    is_dir: bool
    length: int
    """For files: byte size. For directories: child-end index in the FST."""
    fst_index: int
    """Index of this node in the raw FST node array."""

    def __repr__(self) -> str: ...

class FstIter:
    """Iterator returned by :meth:`Fst.__iter__`."""

    def __iter__(self) -> FstIter: ...
    def __next__(self) -> FstNode: ...

class Fst:
    """View of the file system table for an open partition."""

    def find(self, path: str) -> FstNode | None:
        """Find a file or directory by path (case-insensitive).

        The leading ``/`` is optional. Returns ``None`` if not found.
        """

    def __iter__(self) -> FstIter:
        """Iterate over every file and directory in depth-first order."""

    def __repr__(self) -> str: ...

class PartitionMeta:
    """Raw binary partition data (headers, DOL, FST, etc.)."""

    raw_boot: bytes
    """Disc and boot header — ``boot.bin`` (0x440 bytes)."""
    raw_bi2: bytes
    """Debug and region information — ``bi2.bin`` (0x2000 bytes)."""
    raw_apploader: bytes
    """Apploader binary — ``apploader.bin``."""
    raw_dol: bytes
    """Main executable — ``main.dol``."""
    raw_fst: bytes
    """Raw file system table — ``fst.bin``."""
    raw_ticket: bytes | None
    """Wii ticket — ``ticket.bin``. ``None`` for GameCube."""
    raw_tmd: bytes | None
    """Wii title metadata — ``tmd.bin``. ``None`` for GameCube."""
    raw_cert_chain: bytes | None
    """Wii certificate chain — ``cert.bin``. ``None`` for GameCube."""
    raw_h3_table: bytes | None
    """Wii H3 hash table — ``h3.bin``. ``None`` for GameCube."""

    def fst(self) -> Fst:
        """Parse and return the file system table."""

    def disc_header(self) -> DiscHeader:
        """Parse the disc header from ``raw_boot``."""

    def __repr__(self) -> str: ...

class PartitionReader:
    """Read stream for an open disc partition."""

    def is_wii(self) -> bool:
        """Returns ``True`` for Wii partitions, ``False`` for GameCube."""

    def meta(self) -> PartitionMeta:
        """Read the partition header and file system metadata."""

    def read_file(self, node: FstNode) -> FileReader:
        """Open a file identified by *node* for lazy on-demand reading.

        Returns a :class:`FileReader` positioned at the start of the file.
        Data is read from the source disc only when you call
        :meth:`FileReader.read`.

        Raises :exc:`IsADirectoryError` if *node* is a directory.
        """

    def __repr__(self) -> str: ...

class DiscReader:
    """Reader for a GameCube or Wii disc image.

    Supports ISO, CISO, GCZ, NFS, RVZ, WBFS, WIA, and TGC formats.

    Raises :exc:`FileNotFoundError` if the file does not exist.
    Raises :exc:`OSError` if the file cannot be opened or the format is not recognised.

    Example::

        import nod

        disc = nod.DiscReader("game.iso")
        partition = disc.open_partition_kind("Data")
        meta = partition.meta()
        fst = meta.fst()
        node = fst.find("/MP3/Worlds.txt")
        if node:
            data = partition.read_file(node)
    """

    def __init__(self, path: str) -> None: ...
    def header(self) -> DiscHeader:
        """Return the disc's primary header."""

    def meta(self) -> DiscMeta:
        """Return metadata about the underlying file format."""

    def disc_size(self) -> int:
        """Return the disc size in bytes."""

    def partitions(self) -> list[PartitionInfo]:
        """Return Wii partition list. Always empty for GameCube discs."""

    def open_partition(
        self,
        index: int,
        validate_hashes: bool = False,
    ) -> PartitionReader:
        """Open a partition by index. For GameCube discs *index* must be ``0``."""

    def open_partition_kind(
        self,
        kind: str = "Data",
        validate_hashes: bool = False,
    ) -> PartitionReader:
        """Open the first partition matching *kind*.

        *kind* must be one of ``"Data"``, ``"Update"``, or ``"Channel"``.
        For GameCube discs use ``"Data"``.

        Raises :exc:`ValueError` for unknown kind strings.
        """

    def __repr__(self) -> str: ...

class DiscFinalization:
    """Checksums and header data produced after :meth:`DiscWriter.process` completes."""

    crc32: int | None
    """CRC-32 checksum of the input disc data, if requested."""
    xxh64: int | None
    """XXH64 checksum of the input disc data, if requested."""

    @property
    def md5(self) -> bytes | None:
        """MD5 hash of the input disc data (16 bytes), or ``None`` if not requested."""

    @property
    def sha1(self) -> bytes | None:
        """
        SHA-1 hash of the input disc data (20 bytes), or ``None`` if not requested.
        """

    @property
    def header(self) -> bytes:
        """
        Header bytes that were written to the start of the output file (may be empty).
        """

    def __repr__(self) -> str: ...

class DiscWriter:
    """Writer for converting a disc image to a different format.

    Construct by passing a :class:`DiscReader` and target format::

        disc = nod.DiscReader("game.rvz")
        writer = nod.DiscWriter(disc, "ISO")
        fin = writer.process("output.iso", digest_crc32=True)
        print(f"CRC32: {fin.crc32:#010x}")
    """

    def __init__(
        self,
        disc: DiscReader,
        format: str,
        compression: str | None = None,
        block_size: int = 0,
    ) -> None:
        """Create a writer targeting *format*.

        *format* is one of ``"ISO"``, ``"CISO"``, ``"GCZ"``, ``"RVZ"``,
        ``"WBFS"``, ``"WIA"``, ``"TGC"``.

        *compression* follows the pattern ``"Algorithm"`` or ``"Algorithm:level"``,
        e.g. ``"Zstandard:19"``, ``"Lzma2:6"``, ``"None"``.
        Defaults to the recommended compression for *format*.

        *block_size* defaults to the recommended block size for *format*
        (``0`` = use default).
        """

    def progress_bound(self) -> int:
        """
        Upper bound for the *progress* value passed to the :meth:`process` callback.
        """

    def process(
        self,
        output_path: str,
        *,
        callback: Callable[[int, int], None] | None = None,
        digest_crc32: bool = False,
        digest_md5: bool = False,
        digest_sha1: bool = False,
        digest_xxh64: bool = False,
        scrub_update_partition: bool = False,
    ) -> DiscFinalization:
        """Convert and write the disc image to *output_path*.

        An optional *callback* ``(progress: int, total: int) -> None`` is called after
        each chunk is written and can be used to display progress.

        Set ``digest_*`` flags to compute and return the corresponding checksums.

        Set *scrub_update_partition* to replace the Wii update partition with zeroes
        (supported for WBFS and CISO only).

        Raises :exc:`OSError` if the output file cannot be created or written.
        """

    def __repr__(self) -> str: ...

class DiscPatcher:
    """Patches or extends a GameCube disc by adding or replacing files.

    The result of :meth:`build` is a :class:`DiscReader` that can be passed
    directly to :class:`DiscWriter` for conversion to any supported output format.

    Only GameCube discs are supported.

    Example::

        disc = nod.DiscReader("original.iso")
        patcher = nod.DiscPatcher(disc)
        with open("new_audio.dsp", "rb") as f:
            patcher.add_file("files/audio/bgm.dsp", f.read())
        patched = patcher.build()
        nod.DiscWriter(patched, "ISO").process("patched.iso")
    """

    def __init__(self, disc: DiscReader) -> None:
        """Create a patcher for *disc*.

        Raises :exc:`ValueError` if *disc* is a Wii disc.
        """

    def set_dol(self, data: bytes) -> None:
        """Replace the main executable (DOL) in the patched disc.

        *data* must be a valid DOL binary. Calling this a second time
        replaces the previous override.
        """

    def add_file(self, path: str, data: bytes) -> None:
        """Add a new file or replace an existing one.

        *path* is the FST path (e.g. ``"files/audio/bgm.dsp"``). Leading
        slashes are stripped. Calling this again with the same path replaces
        the previous data.

        Raises :exc:`ValueError` if *path* starts with ``"sys/"``.
        """

    def set_header(
        self,
        *,
        game_id: str | None = None,
        game_title: str | None = None,
        disc_num: int | None = None,
        disc_version: int | None = None,
        audio_streaming: bool | None = None,
        audio_stream_buf_size: int | None = None,
    ) -> None:
        """Override disc header fields in the patched disc.

        All parameters are keyword-only and optional; only those provided
        are changed.

        Raises :exc:`ValueError` if *game_id* is not exactly 6 characters.
        """

    def build(self) -> DiscReader:
        """Build a patched :class:`DiscReader` with all overrides applied.

        Reads all files from the source disc into memory, substituting any
        overrides added via :meth:`add_file`, then returns a new
        :class:`DiscReader` ready for :class:`DiscWriter`.

        New files (paths not present in the original FST) are appended.

        Raises :exc:`OSError` if the source disc cannot be read.
        Raises :exc:`RuntimeError` if the disc layout is invalid.
        """

    def __repr__(self) -> str: ...
