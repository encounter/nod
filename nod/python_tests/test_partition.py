import pytest

import nod


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
        data = partition.read_file(node)
        assert isinstance(data, bytes)
        assert len(data) == node.length

    def test_read_file_correct_size(self, partition: nod.PartitionReader, fst: nod.Fst):
        # Verify a handful of files have the expected size
        checked = 0
        for node in fst:
            if node.is_file and node.length > 0:
                data = partition.read_file(node)
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
