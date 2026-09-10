# SANCTUM

**Integrated Secure Data Erasure & Forensic Recovery Platform**

A single desktop tool that does three jobs that are normally three separate
products:

1. **Secure Drive Eraser** — sanitize whole devices and disk images to a named
   standard, with read-back verification and a tamper-evident audit record.
2. **Secure File & Folder Eraser** — selective secure deletion that overwrites
   content, removes the metadata around it, and reports honestly about what it
   cannot reach.
3. **Advanced File Carving & Recovery** — recover files from formatted, damaged
   or wiped media by content, structure and confidence — without relying on
   filesystem metadata.

Everything the tool does is recorded in a hash-chained audit log and can be
exported as a compliance report in HTML, JSON and CSV.

---

## Why this is not a toy

Most student forensic tools find files by looking for a header and then a
footer. That approach fails on the first real-world case, and it fails
*silently* — it produces a truncated file that looks recovered.

SANCTUM does structural end-detection instead. A JPEG is walked marker by
marker; a PNG is walked chunk by chunk to `IEND`; a ZIP is resolved through its
end-of-central-directory record; a PDF is read to its last `%%EOF`. The reason
this matters is concrete: **a JPEG's EXIF block frequently contains a complete
embedded thumbnail, with its own `FFD9` end-of-image marker.** A naive carver
stops there and hands back a corrupt fragment. There is a test in this
repository that constructs exactly that file and fails any carver that gets it
wrong (`tests/test_carver.py::test_embedded_thumbnail_does_not_truncate_the_jpeg`).

The same instinct runs through the erasure side. Overwriting a drive is a
genuine purge on magnetic media. On an SSD it is **not**, because wear-levelling
and block remapping mean the controller decides where writes actually land —
the blocks holding the old data may never be touched. SANCTUM says so, in the
result, in the UI and in the report, rather than printing "verified" and letting
the operator believe something untrue.

---

## Quick start

```bash
# 1. Build the synthetic evidence images (no real device needed)
python run.py --make-media testdata

# 2. Check the whole thing works, headless, and see real numbers
python run.py --selftest

# 3. Launch the desktop application
pip install PyQt6
python run.py
```

`--selftest` exercises all three modules against generated media and prints what
it measured — recall against SHA-256 ground truth, verification results, and
whether tampering with the audit log is detected. It is the fastest way to see
whether the tool is working on a given machine.

### Running the tests

```bash
pip install pytest
python -m pytest tests -q
```

---

## Requirements

| Component | Required? | Notes |
|---|---|---|
| Python 3.11+ | **Yes** | Developed and tested on 3.11 and 3.13 |
| PyQt6 | For the GUI | The engines and `--selftest` work without it |
| pytest | For the tests | |
| pytsk3, pyewf | Optional | Filesystem-aware recovery and E01 images |

**The three engines, the audit chain and the report writer have no third-party
dependencies at all.** That is a deliberate constraint: a forensic tool whose
core fails to install on the examiner's workstation is not a tool. The optional
native backend adds capability where it is available and degrades cleanly where
it is not — the Recovery page shows which capabilities are live.

---

## Safety design

SANCTUM can destroy data. The design assumes that is the failure mode worth
engineering against, so committing a **real device** requires several
independent things to be true at once:

| Gate | Default | Effect |
|---|---|---|
| `SafetyPolicy.allow_raw_devices` | `False` | Must be enabled in Settings |
| `SANCTUM_ALLOW_RAW_DEVICE` env var | unset | Second key, held outside the app |
| Typed confirmation token | required | Derived from path+size+serial; cannot be guessed |
| `SafetyPolicy.dry_run` | **`True`** | Nothing is written until switched off |

In addition, and unconditionally:

- The **running operating-system drive** is refused. There is no override.
- SANCTUM's **own data directory** is refused.
- The typed token is derived from `sha256(path|size|serial|kind)`, so it changes
  if the device at that path changes — a token obtained for one drive does not
  authorise another.

The default configuration cannot destroy anything. Every refusal is itself
written to the audit chain, so an attempt is as visible as an action.

Disk **images** are the default working mode and are not gated the same way,
because a file the operator created is not a device the operator might have
misidentified.

---

## What the tool will not claim

Honesty about limits is a feature, and it is enforced in code rather than left
to the operator's judgement. Every report states the limitations that apply to
the operations it actually describes:

- **Overwrite is not a purge on flash media.** On SSD, NVMe, USB flash and SD
  cards, wear-levelling means an overwrite cannot be shown to have reached the
  blocks holding the original data. The correct tools there are ATA SANITIZE /
  SECURITY ERASE UNIT, NVMe Format/Sanitize, or a TCG Opal crypto erase.
- **Free-space sweeping does not touch journaling or log-structured
  filesystems.** `$LogFile` on NTFS, the ext3/4 journal, and copy-on-write
  filesystems such as btrfs hold prior content that a free-space fill does not
  reliably overwrite.
- **Carving cannot reassemble every fragmented file.** Files whose extents are
  no longer contiguous may be recovered partially or not at all, and the
  report says which.
- **Confidence scores are heuristic and are shown with their arithmetic.**
  Every score is the exact sum of named, individually-weighted factors that are
  retained in the output, so a reviewer can recompute or reweight it.
- **The audit chain is tamper-*evident*, not tamper-*proof*.** It detects
  modification, reordering, deletion and sequence gaps. An attacker who can
  rewrite the entire file can produce a shorter chain that still verifies —
  this is a pinned, documented limitation, not an oversight.

---

## Repository layout

```
sanctum/
  config.py            Runtime configuration and the safety policy
  cases.py             Cases, evidence register, chain of custody
  core/
    hashing.py         Digests and streaming hash helpers
    audit.py           Hash-chained, HMAC-sealed audit log
    standards.py       The 9 overwrite standards and their pass patterns
    targets.py         Target abstraction, device probing, safety gates
    devices.py         Cross-platform device enumeration
    progress.py        Progress reporting and cooperative cancellation
  erase/
    drive.py           Module 1 - drive and image sanitization
    file.py            Module 2 - selective file/folder erasure
    verify.py          Read-back verification (full / sampled)
  recover/
    signatures.py      37 file signatures and their structural validators
    carver.py          Module 3 - block-wise signature carving
    classify.py        Confidence scoring with auditable factors
    fragments.py       Fragmented-file reassembly
    image.py           Image container handling
    native.py          Optional pytsk3/pyewf backend
  report/
    builder.py         HTML / JSON / CSV report generation
    templates.py       Report markup
  gui/                 PyQt6 desktop interface
tools/
  sample_files.py      Generators for valid sample files (no third-party deps)
  fat16.py             A spec-correct FAT16 image builder
  make_test_media.py   Builds the demo and validation media
  benchmark.py         Performance evaluation harness
tests/                 Fourteen test modules, one per subsystem
docs/                  Architecture, user manual, validation, performance
```

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design, data flow, and the reasoning behind the major decisions |
| [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md) | Task-by-task operating instructions |
| [`docs/VALIDATION.md`](docs/VALIDATION.md) | Test strategy, what is verified, and what is not |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | Measurement methodology and how to reproduce it |

---

## Status

The engines, the audit chain, the report writer, the case manager, the test
suite and the desktop interface are implemented. Build and test instructions are
above; `python run.py --selftest` reports the actual state of the installation on
your machine, which is the only claim about it worth trusting.

Regards,
Kartik Kashyap (Primary Author)
Team Drishti — Smart India Hackathon 2026.