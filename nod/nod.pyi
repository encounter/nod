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

    def read_file(self, node: FstNode) -> bytes:
        """Read the full contents of a file identified by *node*.

        Raises :exc:`OSError` if *node* is a directory.
        """

    def __repr__(self) -> str: ...

class DiscReader:
    """Reader for a GameCube or Wii disc image.

    Construct with :func:`open`.
    """

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

def open(path: str) -> DiscReader:
    """Open a disc image from *path*.

    Supports ISO, CISO, GCZ, NFS, RVZ, WBFS, WIA, and TGC formats.

    Raises :exc:`OSError` if the file cannot be opened or the format is not recognised.

    Example::

        import nod

        disc = nod.open("game.iso")
        partition = disc.open_partition_kind("Data")
        meta = partition.meta()
        fst = meta.fst()
        node = fst.find("/MP3/Worlds.txt")
        if node:
            data = partition.read_file(node)
    """
