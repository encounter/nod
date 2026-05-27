import pytest

import nod_rs as nod


class TestPartitionReader:
    def test_is_wii(self, disc: nod.DiscReader, partition: nod.PartitionReader):
        header = disc.header()
        assert partition.is_wii() == header.is_wii

    def test_repr(self, partition: nod.PartitionReader):
        r = repr(partition)
        assert "PartitionReader" in r
        assert "is_wii" in r

    def test_meta_returns_object(self, partition_meta: nod.PartitionMeta):
        assert partition_meta is not None

    def test_meta_repr(self, partition_meta: nod.PartitionMeta):
        assert "PartitionMeta" in repr(partition_meta)

    def test_meta_disc_header(self, partition_meta: nod.PartitionMeta):
        header = partition_meta.disc_header()
        assert isinstance(header, nod.DiscHeader)
        assert len(header.game_id) == 6

    def test_meta_raw_boot(self, partition_meta: nod.PartitionMeta):
        raw = partition_meta.raw_boot
        assert isinstance(raw, bytes)
        assert len(raw) == 0x440  # BOOT_SIZE

    def test_meta_raw_bi2(self, partition_meta: nod.PartitionMeta):
        raw = partition_meta.raw_bi2
        assert isinstance(raw, bytes)
        assert len(raw) == 0x2000  # BI2_SIZE

    def test_meta_raw_apploader(self, partition_meta: nod.PartitionMeta):
        raw = partition_meta.raw_apploader
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_meta_raw_dol(self, partition_meta: nod.PartitionMeta):
        raw = partition_meta.raw_dol
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_meta_raw_fst(self, partition_meta: nod.PartitionMeta):
        raw = partition_meta.raw_fst
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_meta_wii_fields_absent_for_gamecube(
        self, disc: nod.DiscReader, partition_meta: nod.PartitionMeta
    ):
        if disc.header().is_gamecube:
            assert partition_meta.raw_ticket is None
            assert partition_meta.raw_tmd is None
            assert partition_meta.raw_cert_chain is None
            assert partition_meta.raw_h3_table is None


class TestFst:
    def test_fst_iter_yields_nodes(self, fst: nod.Fst):
        nodes = list(fst)
        assert len(nodes) > 0

    def test_fst_iter_node_fields(self, fst: nod.Fst):
        for node in fst:
            assert isinstance(node.name, str)
            assert isinstance(node.path, str)
            assert isinstance(node.is_file, bool)
            assert isinstance(node.is_dir, bool)
            assert isinstance(node.length, int)
            assert isinstance(node.fst_index, int)
            assert node.is_file != node.is_dir
            assert node.length >= 0

    def test_fst_iter_paths_non_empty(self, fst: nod.Fst):
        for node in fst:
            assert len(node.path) > 0

    def test_fst_iter_file_length_positive(self, fst: nod.Fst):
        for node in fst:
            if node.is_file:
                assert node.length > 0

    def test_fst_find_missing(self, fst: nod.Fst):
        assert fst.find("/this/path/does/not/exist") is None

    def test_fst_find_case_insensitive(self, fst: nod.Fst):
        # Collect all file paths from iteration
        nodes = list(fst)
        if not nodes:
            pytest.skip("FST is empty")
        first_file = next((n for n in nodes if n.is_file), None)
        if first_file is None:
            pytest.skip("No files in FST")
        # Searching with different case should still find it
        upper = "/" + first_file.path.upper()
        lower = "/" + first_file.path.lower()
        assert fst.find(upper) is not None
        assert fst.find(lower) is not None

    def test_fst_node_repr(self, fst: nod.Fst):
        for node in fst:
            r = repr(node)
            assert "FstNode" in r
            assert node.path in r
            break

    def test_read_small_file(self, partition: nod.PartitionReader, fst: nod.Fst):
        # Find the smallest file in the FST and read it
        files = sorted(
            (n for n in fst if n.is_file and n.length > 0),
            key=lambda n: n.length,
        )
        if not files:
            pytest.skip("No readable files in FST")
        node = files[0]
        f = partition.read_file(node)
        assert isinstance(f, nod.FileReader)
        data = f.read()
        assert isinstance(data, bytes)
        assert len(data) == node.length

    def test_read_file_correct_size(self, partition: nod.PartitionReader, fst: nod.Fst):
        # Verify a handful of files have the expected size
        checked = 0
        for node in fst:
            if node.is_file and node.length > 0:
                data = partition.read_file(node).read()
                assert len(data) == node.length, (
                    f"{node.path}: expected {node.length} bytes, got {len(data)}"
                )
                checked += 1
                if checked >= 5:
                    break

    def test_read_file_on_directory_raises(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        dir_node = next((n for n in fst if n.is_dir), None)
        if dir_node is None:
            pytest.skip("No directories in FST")
        with pytest.raises(IsADirectoryError):
            partition.read_file(dir_node)


# ---------------------------------------------------------------------------
# FileReader — seeking and partial reads
# ---------------------------------------------------------------------------


def _file_with_min_size(fst: nod.Fst, min_size: int) -> nod.FstNode:
    """Return the smallest file that is at least *min_size* bytes, or skip."""
    candidates = sorted(
        (n for n in fst if n.is_file and n.length >= min_size),
        key=lambda n: n.length,
    )
    if not candidates:
        pytest.skip(f"No file with at least {min_size} bytes in FST")
    return candidates[0]


class TestFileReader:
    def test_size_matches_fst_node(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        assert f.size() == node.length

    def test_tell_starts_at_zero(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        assert f.tell() == 0

    def test_tell_advances_after_read(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 4)
        f = partition.read_file(node)
        f.read(4)
        assert f.tell() == 4

    def test_read_all_matches_size(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 1)
        data = partition.read_file(node).read()
        assert len(data) == node.length

    def test_read_zero_bytes(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 1)
        data = partition.read_file(node).read(0)
        assert data == b""

    def test_partial_read_returns_correct_count(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 8)
        f = partition.read_file(node)
        chunk = f.read(4)
        assert len(chunk) == 4

    def test_two_partial_reads_concatenate_to_full(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 8)
        f = partition.read_file(node)
        half = node.length // 2
        a = f.read(half)
        b = f.read()
        full = partition.read_file(node).read()
        assert a + b == full

    def test_read_past_eof_returns_remaining(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        data = f.read(node.length + 1024)
        assert len(data) == node.length

    def test_read_after_eof_returns_empty(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        f.read()
        assert f.read() == b""
        assert f.read(16) == b""

    def test_seek_from_start(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 8)
        f = partition.read_file(node)
        pos = f.seek(4)
        assert pos == 4
        assert f.tell() == 4

    def test_seek_from_current(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 8)
        f = partition.read_file(node)
        f.seek(4)
        pos = f.seek(2, 1)
        assert pos == 6

    def test_seek_from_end(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 4)
        f = partition.read_file(node)
        pos = f.seek(-4, 2)
        assert pos == node.length - 4

    def test_seek_to_start_rereads_same_data(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 4)
        f = partition.read_file(node)
        first = f.read(4)
        f.seek(0)
        second = f.read(4)
        assert first == second

    def test_seek_and_read_middle(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 8)
        f = partition.read_file(node)
        full = f.read()
        f.seek(4)
        chunk = f.read(4)
        assert chunk == full[4:8]

    def test_multiple_readers_independent(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        # Two FileReaders on the same node must not interfere with each other.
        node = _file_with_min_size(fst, 8)
        f1 = partition.read_file(node)
        f2 = partition.read_file(node)
        first4_f1 = f1.read(4)
        first4_f2 = f2.read(4)
        assert first4_f1 == first4_f2
        # f2 still at position 4 regardless of what f1 does
        f1.read()
        next4_f2 = f2.read(4)
        full = partition.read_file(node).read()
        assert next4_f2 == full[4:8]

    def test_context_manager_closes(self, partition: nod.PartitionReader, fst: nod.Fst):
        node = _file_with_min_size(fst, 1)
        with partition.read_file(node) as f:
            assert not f.closed
            f.read(1)
        assert f.closed

    def test_read_after_close_raises(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        f.close()
        with pytest.raises(ValueError, match="closed"):
            f.read()

    def test_seek_after_close_raises(
        self, partition: nod.PartitionReader, fst: nod.Fst
    ):
        node = _file_with_min_size(fst, 1)
        f = partition.read_file(node)
        f.close()
        with pytest.raises(ValueError, match="closed"):
            f.seek(0)
