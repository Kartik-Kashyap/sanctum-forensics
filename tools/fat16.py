"""
A minimal but spec-correct FAT16 image builder.

Why build a filesystem from scratch rather than ship a pre-made image?

Because the test suite needs *ground truth*. When the builder plants a file at a
known cluster, deletes the directory entry, and frees the FAT chain, the test
knows exactly which bytes should be recoverable and where. A downloaded sample
image gives no such guarantee, and a hand-waved "fake" format would not exercise
the carver's real code paths.

The implementation follows the FAT16 specification: boot sector, two FAT
copies, fixed-size root directory, and a data region addressed through a
cluster chain. Files can be written with an explicit cluster list, which is how
the fragmentation scenarios are constructed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

FREE_ENTRY = 0x00
DELETED_ENTRY = 0xE5
END_OF_CHAIN = 0xFFFF
FREE_CLUSTER = 0x0000
BAD_CLUSTER = 0xFFF7

_INVALID_SHORT_CHARS = set('"*+,/:;<=>?[\\]|')


@dataclass
class DirEntry:
    """One 32-byte directory record."""

    name: str
    extension: str
    attributes: int
    first_cluster: int
    size: int
    deleted: bool = False
    raw_offset: int = 0

    @property
    def filename(self) -> str:
        return f"{self.name}.{self.extension}" if self.extension else self.name

    def to_bytes(self) -> bytes:
        name = self.name.upper().ljust(8)[:8]
        extension = self.extension.upper().ljust(3)[:3]
        first = 0x0000 if self.deleted else self.first_cluster
        size = 0 if self.deleted else self.size

        entry = bytearray(32)
        entry[0:8] = name.encode("ascii", errors="replace")
        entry[8:11] = extension.encode("ascii", errors="replace")
        entry[11] = self.attributes
        entry[12] = 0
        # Creation time/date, deliberately fixed so images are reproducible.
        struct.pack_into("<H", entry, 14, 0x6000)
        struct.pack_into("<H", entry, 16, 0x5A21)  # 2025-01-01
        struct.pack_into("<H", entry, 18, 0x5A21)
        struct.pack_into("<H", entry, 22, 0x6000)
        struct.pack_into("<H", entry, 24, 0x5A21)
        struct.pack_into("<H", entry, 26, first)
        struct.pack_into("<I", entry, 28, size)
        if self.deleted:
            entry[0] = DELETED_ENTRY
        return bytes(entry)

    def as_dict(self) -> dict:
        return {
            "name": self.filename,
            "attributes": f"0x{self.attributes:02X}",
            "first_cluster": self.first_cluster,
            "size": self.size,
            "deleted": self.deleted,
        }


@dataclass
class Fat16Params:
    """Derived geometry for a FAT16 volume."""

    total_sectors: int = 32768          # 16 MiB
    bytes_per_sector: int = 512
    sectors_per_cluster: int = 4        # 2 KiB clusters
    reserved_sectors: int = 1
    num_fats: int = 2
    root_entries: int = 512
    media_descriptor: int = 0xF8
    volume_label: str = "SANCTUMTEST"

    fat_size_sectors: int = 0
    root_dir_sectors: int = 0
    first_data_sector: int = 0
    cluster_count: int = 0

    def finalise(self) -> "Fat16Params":
        """Resolve the circular FAT-size dependency by iteration."""
        self.root_dir_sectors = (
            self.root_entries * 32 + (self.bytes_per_sector - 1)
        ) // self.bytes_per_sector

        fat_size = 1
        while True:
            data_sectors = self.total_sectors - (
                self.reserved_sectors + self.num_fats * fat_size + self.root_dir_sectors
            )
            clusters = data_sectors // self.sectors_per_cluster
            proposed = ((clusters + 2) * 2 + (self.bytes_per_sector - 1)) // self.bytes_per_sector
            if proposed == fat_size:
                break
            fat_size = proposed

        self.fat_size_sectors = fat_size
        self.cluster_count = (
            self.total_sectors
            - (self.reserved_sectors + self.num_fats * fat_size + self.root_dir_sectors)
        ) // self.sectors_per_cluster
        self.first_data_sector = (
            self.reserved_sectors + self.num_fats * fat_size + self.root_dir_sectors
        )
        return self

    @property
    def cluster_size(self) -> int:
        return self.sectors_per_cluster * self.bytes_per_sector

    @property
    def total_bytes(self) -> int:
        return self.total_sectors * self.bytes_per_sector

    def as_dict(self) -> dict:
        return {
            "total_bytes": self.total_bytes,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "fat_size_sectors": self.fat_size_sectors,
            "root_dir_sectors": self.root_dir_sectors,
            "first_data_sector": self.first_data_sector,
        }


class Fat16Image:
    """
    An in-memory FAT16 volume that can be built, mutated and serialised.

    Example - plant a file, then delete it leaving the data in free clusters::

        image = Fat16Image().format()
        image.write_file("SECRET.TXT", b"classified")
        image.delete("SECRET.TXT", free_clusters=True)
        image.save("deleted.img")
    """

    def __init__(self, params: Fat16Params | None = None) -> None:
        self.params = (params or Fat16Params()).finalise()
        self.fat: list[int] = []
        self.root: list[DirEntry] = []
        self.clusters: list[bytearray] = []
        self.deleted_history: list[DirEntry] = []
        self._format()

    # -- construction ------------------------------------------------------

    def _format(self) -> None:
        count = self.params.cluster_count
        self.fat = [FREE_CLUSTER] * (count + 2)
        self.fat[0] = 0xFFF8 | (self.params.media_descriptor & 0x0F)
        self.fat[1] = END_OF_CHAIN
        self.root = []
        self.clusters = [bytearray(self.params.cluster_size) for _ in range(count)]
        self.deleted_history = []

    def format(self) -> "Fat16Image":
        self._format()
        return self

    # -- cluster helpers ---------------------------------------------------

    def _alloc_contiguous(self, how_many: int) -> list[int]:
        """Allocate a run of free clusters, preferring contiguity."""
        if how_many == 0:
            return []
        run_start = None
        run_length = 0
        for index in range(2, len(self.fat)):
            if self.fat[index] == FREE_CLUSTER:
                if run_start is None:
                    run_start = index
                run_length += 1
                if run_length == how_many:
                    return list(range(run_start, run_start + how_many))
            else:
                run_start = None
                run_length = 0
        # Fall back to scattered allocation when no run is long enough.
        allocated = [
            index for index in range(2, len(self.fat)) if self.fat[index] == FREE_CLUSTER
        ][:how_many]
        if len(allocated) < how_many:
            raise OSError(
                f"Volume is full: needed {how_many} clusters, found {len(allocated)} free"
            )
        return allocated

    def _link(self, chain: list[int]) -> None:
        for position, cluster in enumerate(chain):
            self.fat[cluster] = chain[position + 1] if position + 1 < len(chain) else END_OF_CHAIN

    def chain_of(self, first_cluster: int) -> list[int]:
        """Follow a cluster chain, guarding against loops."""
        chain: list[int] = []
        current = first_cluster
        seen: set[int] = set()
        while 2 <= current < len(self.fat) and current not in seen:
            seen.add(current)
            chain.append(current)
            nxt = self.fat[current]
            if nxt >= END_OF_CHAIN - 7 or nxt < 2:
                break
            current = nxt
        return chain

    def free_clusters(self) -> list[int]:
        return [i for i in range(2, len(self.fat)) if self.fat[i] == FREE_CLUSTER]

    def free_cluster_count(self) -> int:
        return len(self.free_clusters())

    # -- file operations ---------------------------------------------------

    def _short_name(self, filename: str) -> tuple[str, str]:
        """Convert a filename to a unique 8.3 short name."""
        stem, _, extension = filename.rpartition(".")
        if not stem:
            stem, extension = filename, ""

        def clean(value: str, limit: int) -> str:
            kept = [
                c
                for c in value.upper()
                if c.isalnum() or c in "-_"
            ]
            return "".join(kept)[:limit]

        stem = clean(stem, 8) or "FILE"
        extension = clean(extension, 3)

        taken = {e.filename for e in self.root if not e.deleted}
        candidate = stem
        suffix = 1
        while True:
            full = f"{candidate}.{extension}" if extension else candidate
            if full not in taken:
                return candidate, extension
            candidate = f"{stem[:6]}~{suffix}"
            suffix += 1

    def write_file(
        self,
        filename: str,
        data: bytes,
        *,
        chain: list[int] | None = None,
        attributes: int = ATTR_ARCHIVE,
    ) -> DirEntry:
        """
        Create a file.

        Supplying ``chain`` forces the file onto specific clusters, which is how
        the fragmentation fixtures are built.
        """
        name, extension = self._short_name(filename)
        needed = (len(data) + self.params.cluster_size - 1) // self.params.cluster_size

        if chain is None:
            chain = self._alloc_contiguous(needed)
        elif len(chain) < needed:
            raise ValueError(
                f"Provided chain has {len(chain)} clusters but {needed} are required"
            )
        else:
            chain = chain[:needed]

        for cluster in chain:
            if self.fat[cluster] != FREE_CLUSTER:
                raise ValueError(f"Cluster {cluster} is already allocated")

        self._link(chain)

        # Scatter the payload across the chain, one cluster at a time.
        for index, cluster in enumerate(chain):
            start = index * self.params.cluster_size
            block = data[start : start + self.params.cluster_size]
            self.clusters[cluster - 2] = bytearray(self.params.cluster_size)
            self.clusters[cluster - 2][: len(block)] = block

        entry = DirEntry(
            name=name,
            extension=extension,
            attributes=attributes,
            first_cluster=chain[0] if chain else 0,
            size=len(data),
        )
        entry.raw_offset = len(self.root) * 32
        self.root.append(entry)
        return entry

    def delete(self, filename: str, *, free_clusters: bool = True) -> DirEntry:
        """
        Delete a file by marking its directory entry.

        ``free_clusters=True`` is the realistic case: the FAT chain is zeroed so
        the clusters become available again, while the payload bytes survive
        untouched in what is now unallocated space. That is precisely the
        condition content-based carving exists to recover from.

        ``free_clusters=False`` models the rarer case where only the directory
        entry is gone and the chain survives - recoverable with filesystem
        structure rather than carving.
        """
        target = filename.upper()
        stem, _, extension = target.rpartition(".")
        if not stem:
            stem, extension = target, ""

        for entry in self.root:
            if entry.deleted:
                continue
            if entry.name == stem[:8] and entry.extension == extension[:3]:
                if free_clusters:
                    for cluster in self.chain_of(entry.first_cluster):
                        self.fat[cluster] = FREE_CLUSTER
                entry.deleted = True
                self.deleted_history.append(
                    DirEntry(
                        name=entry.name,
                        extension=entry.extension,
                        attributes=entry.attributes,
                        first_cluster=entry.first_cluster,
                        size=entry.size,
                        deleted=True,
                    )
                )
                return entry
        raise KeyError(f"No such file in image: {filename}")

    def list_files(self, include_deleted: bool = True) -> list[DirEntry]:
        return [e for e in self.root if include_deleted or not e.deleted]

    def read_file(self, entry: DirEntry) -> bytes:
        """Read a file's content, whether or not it is still allocated."""
        chain = self.chain_of(entry.first_cluster)
        if not chain:
            return b""
        data = bytearray()
        for cluster in chain:
            data.extend(self.clusters[cluster - 2])
        return bytes(data[: entry.size])

    # -- serialisation -----------------------------------------------------

    def boot_sector(self) -> bytes:
        params = self.params
        sector = bytearray(params.bytes_per_sector)
        sector[0:3] = b"\xeb\x3c\x90"
        sector[3:11] = b"SANCTUM "
        struct.pack_into("<H", sector, 11, params.bytes_per_sector)
        sector[13] = params.sectors_per_cluster
        struct.pack_into("<H", sector, 14, params.reserved_sectors)
        sector[16] = params.num_fats
        struct.pack_into("<H", sector, 17, params.root_entries)
        struct.pack_into("<H", sector, 19, params.total_sectors if params.total_sectors < 65536 else 0)
        sector[21] = params.media_descriptor
        struct.pack_into("<H", sector, 22, params.fat_size_sectors)
        struct.pack_into("<H", sector, 24, 63)    # sectors per track
        struct.pack_into("<H", sector, 26, 255)   # heads
        struct.pack_into("<I", sector, 28, 0)     # hidden sectors
        struct.pack_into("<I", sector, 32, params.total_sectors)
        sector[36] = 0x80
        sector[38] = 0x29
        struct.pack_into("<I", sector, 39, 0x5A4E4354)  # volume serial
        sector[43:54] = params.volume_label.upper().ljust(11)[:11].encode()
        sector[54:62] = b"FAT16   "
        sector[510:512] = b"\x55\xaa"
        return bytes(sector)

    def fat_bytes(self) -> bytes:
        entries = struct.pack(f"<{len(self.fat)}H", *self.fat)
        size = self.params.fat_size_sectors * self.params.bytes_per_sector
        return entries.ljust(size, b"\x00")[:size]

    def root_bytes(self) -> bytes:
        entries = bytearray()
        for entry in self.root:
            entries.extend(entry.to_bytes())
        size = self.params.root_dir_sectors * self.params.bytes_per_sector
        return bytes(entries).ljust(size, b"\x00")[:size]

    def to_bytes(self) -> bytes:
        params = self.params
        image = bytearray(params.total_bytes)

        # Reserved region: boot sector first, remainder left zeroed.
        image[0 : params.bytes_per_sector] = self.boot_sector()
        cursor = params.reserved_sectors * params.bytes_per_sector

        fat = self.fat_bytes()
        for _ in range(params.num_fats):
            image[cursor : cursor + len(fat)] = fat
            cursor += len(fat)

        root = self.root_bytes()
        image[cursor : cursor + len(root)] = root
        cursor += len(root)

        for cluster in self.clusters:
            image[cursor : cursor + len(cluster)] = cluster
            cursor += len(cluster)

        return bytes(image)

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.to_bytes())
        return destination

    # -- reporting ---------------------------------------------------------

    def manifest(self) -> dict:
        """Ground-truth description, written alongside the image for the tests."""
        return {
            "params": self.params.as_dict(),
            "cluster_size": self.params.cluster_size,
            "entries": [e.as_dict() for e in self.root],
            "deleted_history": [e.as_dict() for e in self.deleted_history],
            "free_clusters": self.free_cluster_count(),
            "allocated_clusters": len(self.fat) - 2 - self.free_cluster_count(),
        }
