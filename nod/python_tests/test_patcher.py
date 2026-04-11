import pytest

import nod


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


class TestDiscPatcherConstruct:
    def test_create(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        assert patcher is not None

    def test_repr_empty(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        r = repr(patcher)
        assert "DiscPatcher" in r
        assert "0" in r

    def test_repr_after_add(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        patcher.add_file("files/test.bin", b"x")
        assert "1" in repr(patcher)
        patcher.add_file("files/test2.bin", b"y")
        assert "2" in repr(patcher)

    def test_wii_disc_raises(self, wii_disc: nod.DiscReader):
        with pytest.raises(ValueError, match="(?i)wii"):
            nod.DiscPatcher(wii_disc)


# ---------------------------------------------------------------------------
# add_file validation
# ---------------------------------------------------------------------------


class TestDiscPatcherAddFile:
    def test_sys_boot_raises(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        with pytest.raises(ValueError, match="sys/"):
            patcher.add_file("sys/boot.bin", b"data")

    def test_sys_dol_raises(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        with pytest.raises(ValueError, match="sys/"):
            patcher.add_file("sys/main.dol", b"data")

    def test_sys_with_leading_slash_raises(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        with pytest.raises(ValueError, match="sys/"):
            patcher.add_file("/sys/apploader.img", b"data")

    def test_normal_path_succeeds(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        patcher.add_file("files/new.bin", b"hello")  # must not raise

    def test_leading_slash_stripped(self, disc: nod.DiscReader):
        # /files/x and files/x should count as the same key
        patcher = nod.DiscPatcher(disc)
        patcher.add_file("/files/dupe.bin", b"first")
        patcher.add_file("files/dupe.bin", b"second")
        assert "1" in repr(patcher)  # only one entry

    def test_override_same_path(self, disc: nod.DiscReader):
        patcher = nod.DiscPatcher(disc)
        patcher.add_file("files/x.bin", b"v1")
        patcher.add_file("files/x.bin", b"v2")
        assert "1" in repr(patcher)  # second call replaced first


# ---------------------------------------------------------------------------
# build() — structural checks
# ---------------------------------------------------------------------------


class TestDiscPatcherBuild:
    def test_build_returns_disc_reader(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        assert isinstance(patched, nod.DiscReader)

    def test_build_preserves_game_id(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        assert patched.header().game_id == disc.header().game_id

    def test_build_preserves_game_title(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        assert patched.header().game_title == disc.header().game_title

    def test_build_is_gamecube(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        assert patched.header().is_gamecube
        assert not patched.header().is_wii

    def test_build_partition_accessible(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        partition = patched.open_partition_kind("Data")
        assert partition is not None
        assert not partition.is_wii()

    def test_build_fst_non_empty(self, disc: nod.DiscReader):
        patched = nod.DiscPatcher(disc).build()
        fst = patched.open_partition_kind("Data").meta().fst()
        nodes = list(fst)
        assert len(nodes) > 0

    def test_build_idempotent(self, disc: nod.DiscReader):
        # Calling build() twice on the same patcher should produce consistent results.
        patcher = nod.DiscPatcher(disc)
        r1 = patcher.build()
        r2 = patcher.build()
        assert r1.header().game_id == r2.header().game_id


# ---------------------------------------------------------------------------
# build() — file content integrity
# ---------------------------------------------------------------------------


class TestDiscPatcherFileIntegrity:
    def _smallest_file(self, disc: nod.DiscReader) -> tuple[nod.PartitionReader, nod.FstNode]:
        partition = disc.open_partition_kind("Data")
        meta = partition.meta()
        files: list[nod.FstNode] = sorted(
            (n for n in meta.fst() if n.is_file and n.length > 0),
            key=lambda n: n.length,
        )
        if not files:
            pytest.skip("No files in FST")
        return partition, files[0]

    def test_unmodified_file_matches_original(self, disc: nod.DiscReader):
        partition, node = self._smallest_file(disc)
        original_data = partition.read_file(node)

        patched = nod.DiscPatcher(disc).build()
        patched_partition = patched.open_partition_kind("Data")
        patched_meta = patched_partition.meta()
        patched_node = patched_meta.fst().find("/" + node.path)
        assert patched_node is not None, f"File {node.path} missing from patched FST"
        patched_data = patched_partition.read_file(patched_node)
        assert patched_data == original_data

    def test_replaced_file_has_new_data(self, disc: nod.DiscReader):
        _, node = self._smallest_file(disc)
        new_data = b"REPLACED" * 16

        patcher = nod.DiscPatcher(disc)
        patcher.add_file(node.path, new_data)
        patched = patcher.build()

        patched_partition = patched.open_partition_kind("Data")
        patched_node = patched_partition.meta().fst().find("/" + node.path)
        assert patched_node is not None
        assert patched_node.length == len(new_data)
        assert patched_partition.read_file(patched_node) == new_data

    def test_replaced_file_different_size(self, disc: nod.DiscReader):
        _, node = self._smallest_file(disc)
        # Use a size guaranteed to be different from the original (original >= 1 byte)
        new_data = b"\xDE\xAD\xBE\xEF" * 64  # 256 bytes

        patcher = nod.DiscPatcher(disc)
        patcher.add_file(node.path, new_data)
        patched = patcher.build()

        patched_partition = patched.open_partition_kind("Data")
        patched_node = patched_partition.meta().fst().find("/" + node.path)
        assert patched_node is not None
        assert patched_node.length == 256
        assert patched_partition.read_file(patched_node) == new_data

    def test_other_files_unchanged_when_one_replaced(self, disc: nod.DiscReader):
        partition = disc.open_partition_kind("Data")
        meta = partition.meta()
        files = sorted(
            (n for n in meta.fst() if n.is_file and n.length > 0),
            key=lambda n: n.length,
        )
        if len(files) < 2:
            pytest.skip("Need at least 2 files in FST")

        target = files[0]
        bystander = files[1]
        original_bystander_data = partition.read_file(bystander)

        patcher = nod.DiscPatcher(disc)
        patcher.add_file(target.path, b"new content")
        patched = patcher.build()

        patched_partition = patched.open_partition_kind("Data")
        patched_bystander = patched_partition.meta().fst().find("/" + bystander.path)
        assert patched_bystander is not None
        assert patched_partition.read_file(patched_bystander) == original_bystander_data

    def test_add_new_file_appears_in_fst(self, disc: nod.DiscReader):
        new_path = "files/__patcher_new_file__.bin"
        new_data = b"brand new file content"

        patcher = nod.DiscPatcher(disc)
        patcher.add_file(new_path, new_data)
        patched = patcher.build()

        patched_partition = patched.open_partition_kind("Data")
        node = patched_partition.meta().fst().find("/" + new_path)
        assert node is not None, f"{new_path} not found in patched FST"
        assert node.length == len(new_data)
        assert patched_partition.read_file(node) == new_data

    def test_all_original_files_present_after_unmodified_build(self, disc: nod.DiscReader):
        partition = disc.open_partition_kind("Data")
        original_paths = {n.path for n in partition.meta().fst() if n.is_file}

        patched = nod.DiscPatcher(disc).build()
        patched_partition = patched.open_partition_kind("Data")
        patched_paths = {n.path for n in patched_partition.meta().fst() if n.is_file}

        missing = original_paths - patched_paths
        assert not missing, f"Files missing from patched disc: {missing}"


# ---------------------------------------------------------------------------
# build() → DiscWriter round-trip
# ---------------------------------------------------------------------------


class TestDiscPatcherWriterRoundtrip:
    def test_patched_disc_writeable_to_iso(self, disc: nod.DiscReader, tmp_path):
        patched = nod.DiscPatcher(disc).build()
        out = tmp_path / "patched.iso"
        nod.DiscWriter(patched, "ISO").process(str(out))
        assert out.stat().st_size > 0

    def test_written_iso_reopens_correctly(self, disc: nod.DiscReader, tmp_path):
        _, node = _smallest_file_in(disc)
        new_data = b"roundtrip_check" * 8

        patcher = nod.DiscPatcher(disc)
        patcher.add_file(node.path, new_data)
        patched = patcher.build()

        out = tmp_path / "patched.iso"
        nod.DiscWriter(patched, "ISO").process(str(out))

        reopened = nod.DiscReader(str(out))
        assert reopened.header().game_id == disc.header().game_id

        repart = reopened.open_partition_kind("Data")
        renode = repart.meta().fst().find("/" + node.path)
        assert renode is not None
        assert repart.read_file(renode) == new_data


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _smallest_file_in(disc: nod.DiscReader):
    partition = disc.open_partition_kind("Data")
    meta = partition.meta()
    files = sorted(
        (n for n in meta.fst() if n.is_file and n.length > 0),
        key=lambda n: n.length,
    )
    if not files:
        pytest.skip("No files in FST")
    return partition, files[0]
