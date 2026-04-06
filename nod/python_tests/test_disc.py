import pytest

import nod


def test_open_nonexistent():
    with pytest.raises(FileNotFoundError):
        nod.open("nonexistent_file.iso")


class TestDiscReader:
    def test_header_game_id(self, disc: nod.DiscReader):
        header = disc.header()
        assert len(header.game_id) == 6
        assert header.game_id.isascii()

    def test_header_game_title(self, disc: nod.DiscReader):
        header = disc.header()
        assert len(header.game_title) > 0

    def test_header_disc_type(self, disc: nod.DiscReader):
        header = disc.header()
        assert header.is_gamecube != header.is_wii

    def test_header_disc_num(self, disc: nod.DiscReader):
        header = disc.header()
        assert header.disc_num == 0

    def test_header_repr(self, disc: nod.DiscReader):
        header = disc.header()
        r = repr(header)
        assert "DiscHeader" in r
        assert header.game_id in r

    def test_meta_format(self, disc: nod.DiscReader):
        meta = disc.meta()
        assert meta.format in {"ISO", "CISO", "GCZ", "NFS", "RVZ", "WBFS", "WIA", "TGC"}

    def test_meta_compression(self, disc: nod.DiscReader):
        meta = disc.meta()
        assert isinstance(meta.compression, str)
        assert len(meta.compression) > 0

    def test_meta_flags(self, disc: nod.DiscReader):
        meta = disc.meta()
        assert isinstance(meta.decrypted, bool)
        assert isinstance(meta.lossless, bool)
        assert isinstance(meta.needs_hash_recovery, bool)

    def test_disc_size(self, disc: nod.DiscReader):
        assert disc.disc_size() > 0

    def test_partitions_gamecube(self, disc: nod.DiscReader):
        # GameCube discs have no Wii partitions
        header = disc.header()
        partitions = disc.partitions()
        if header.is_gamecube:
            assert partitions == []

    def test_open_partition_by_index(self, disc: nod.DiscReader):
        p = disc.open_partition(0)
        assert p is not None

    def test_open_partition_by_kind(self, disc: nod.DiscReader):
        p = disc.open_partition_kind("Data")
        assert p is not None

    def test_open_partition_invalid_kind(self, disc: nod.DiscReader):
        with pytest.raises(ValueError, match="Unknown partition kind"):
            disc.open_partition_kind("Invalid")
