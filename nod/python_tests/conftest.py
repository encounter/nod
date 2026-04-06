import os

import pytest

import nod


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requires_disc: test requires GC_ISO_PATH to be set"
    )


@pytest.fixture(scope="session")
def iso_path() -> str:
    path = os.environ.get("GC_ISO_PATH")
    if not path:
        pytest.skip("GC_ISO_PATH not set")
    return path


@pytest.fixture(scope="session")
def disc(iso_path: str) -> nod.DiscReader:
    return nod.open_disc(iso_path)


@pytest.fixture(scope="session")
def partition(disc: nod.DiscReader) -> nod.PartitionReader:
    return disc.open_partition_kind("Data")


@pytest.fixture(scope="session")
def partition_meta(partition: nod.PartitionReader) -> nod.PartitionMeta:
    return partition.meta()


@pytest.fixture(scope="session")
def fst(partition_meta: nod.PartitionMeta) -> nod.Fst:
    return partition_meta.fst()
