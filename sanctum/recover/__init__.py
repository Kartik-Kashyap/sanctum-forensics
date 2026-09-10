"""
Advanced File Carving and Recovery.

Layers, from most to least dependent on external libraries:

* :mod:`sanctum.recover.native`   - SleuthKit/pyewf: filesystem metadata,
                                    deleted-file enumeration, E01 images
* :mod:`sanctum.recover.carver`   - content-based carving (pure Python)
* :mod:`sanctum.recover.fragments`- fragmented-file reassembly
* :mod:`sanctum.recover.classify` - auto-classification and confidence scoring
* :mod:`sanctum.recover.signatures`- the format database

Every layer below the native backend works with no third-party dependencies, so
the tool always runs; the native layer unlocks depth where it is installed.
"""

from sanctum.recover.carver import CarvedArtifact, CarveResult, SignatureCarver
from sanctum.recover.classify import Classification, summarize_artifacts
from sanctum.recover.fragments import Extent, ReassemblyResult, reassemble_jpeg
from sanctum.recover.image import DiskImage, ImageInfo, detect_container, parse_mbr_partitions
from sanctum.recover.native import (
    NativeCapabilities,
    NativeFilesystem,
    NativeImage,
    capabilities,
)
from sanctum.recover.signatures import (
    SIGNATURES,
    FileSignature,
    categories,
    get_signature,
)

__all__ = [
    "SignatureCarver",
    "CarveResult",
    "CarvedArtifact",
    "Classification",
    "summarize_artifacts",
    "ReassemblyResult",
    "Extent",
    "reassemble_jpeg",
    "DiskImage",
    "ImageInfo",
    "detect_container",
    "parse_mbr_partitions",
    "NativeImage",
    "NativeFilesystem",
    "NativeCapabilities",
    "capabilities",
    "SIGNATURES",
    "FileSignature",
    "get_signature",
    "categories",
]
