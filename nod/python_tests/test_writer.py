import tempfile
from pathlib import Path

import pytest

import nod


class TestDiscWriter:
    def test_create_writer_iso(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        assert writer is not None

    def test_create_writer_invalid_format(self, disc: nod.DiscReader):
        with pytest.raises(ValueError, match="Unknown format"):
            nod.DiscWriter(disc, "INVALID")

    def test_create_writer_invalid_compression(self, disc: nod.DiscReader):
        with pytest.raises(ValueError, match="Unknown compression type"):
            nod.DiscWriter(disc, "RVZ", compression="BadAlgo")

    def test_repr(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        assert "DiscWriter" in repr(writer)

    def test_progress_bound(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        assert writer.progress_bound() > 0

    def test_process_to_iso(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            fin = writer.process(str(out_path))
            assert isinstance(fin, nod.DiscFinalization)
            assert out_path.stat().st_size > 0
        finally:
            out_path.unlink()

    def test_process_to_iso_with_failed_callback(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")

        def failing_callback(progress: int, total: int) -> None:
            raise ValueError("Callback failed!")

        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            with pytest.raises(OSError, match="Failed to write disc data"):
                writer.process(str(out_path), callback=failing_callback)
        finally:
            out_path.unlink()

    def test_process_produces_valid_disc(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            writer.process(str(out_path))
            out_disc = nod.open_disc(str(out_path))
            assert out_disc.header().game_id == disc.header().game_id
            assert out_disc.header().game_title == disc.header().game_title
        finally:
            out_path.unlink()

    def test_process_with_crc32(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            fin = writer.process(str(out_path), digest_crc32=True)
            assert fin.crc32 is not None
            assert isinstance(fin.crc32, int)
        finally:
            out_path.unlink()

    def test_process_with_sha1(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            fin = writer.process(str(out_path), digest_sha1=True)
            assert fin.sha1 is not None
            assert len(fin.sha1) == 20
        finally:
            out_path.unlink()

    def test_process_no_digest_returns_none(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            fin = writer.process(str(out_path))
            assert fin.crc32 is None
            assert fin.md5 is None
            assert fin.sha1 is None
            assert fin.xxh64 is None
        finally:
            out_path.unlink()

    def test_process_bad_output_path(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with pytest.raises(OSError, match="Failed to create"):
            writer.process("/no/such/directory/output.iso")

    def test_finalization_repr(self, disc: nod.DiscReader):
        writer = nod.DiscWriter(disc, "ISO")
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
            out_path = Path(f.name)
        try:
            fin = writer.process(str(out_path), digest_crc32=True)
            assert "DiscFinalization" in repr(fin)
        finally:
            out_path.unlink()
