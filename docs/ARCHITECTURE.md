# SANCTUM — Architecture

This document explains how the tool is put together and, more usefully, *why*.
Where a design decision looks unusual, the reasoning is recorded here so it can
be argued with rather than reverse-engineered.

---

## 1. Layering

```
┌──────────────────────────────────────────────────────────────────┐
│  sanctum/gui          PyQt6 desktop interface                    │
│    app.py    shell, navigation, status                           │
│    views/    one page per task; collects parameters, renders     │
│              results; contains no forensic logic                 │
│    workers.py Job(QThread) - runs one engine call off the GUI    │
│               thread, injecting progress= and cancel=            │
│    state.py  AppState - case, policy, session results            │
│    widgets.py, theme.py                                          │
└───────────────────────────┬──────────────────────────────────────┘
                            │  every engine call takes progress=/cancel=
┌───────────────────────────▼──────────────────────────────────────┐
│  sanctum/erase                    sanctum/recover                │
│    drive.py  Module 1              carver.py    Module 3         │
│    file.py   Module 2              signatures.py                 │
│    verify.py                       classify.py                  │
│                                    fragments.py                 │
│                                    native.py  (optional)        │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│  sanctum/core                                                    │
│    targets.py   safety gates, device probing, TargetWriter       │
│    standards.py 9 overwrite standards and their pass patterns    │
│    audit.py     hash-chained, HMAC-sealed log                    │
│    hashing.py   digests, entropy, human_bytes                    │
│    progress.py  ProgressReporter, CancelToken                    │
│  sanctum/cases.py   cases, evidence register, chain of custody   │
│  sanctum/report/    HTML / JSON / CSV report generation          │
│  sanctum/config.py  policy and paths                             │
└──────────────────────────────────────────────────────────────────┘
```

**The rule that keeps this honest:** a GUI view may collect parameters and
render a result, but it may not implement forensic behaviour. Every operation a
user can trigger is a call into the same function the test suite exercises
directly. There is no second code path that only the GUI takes, which is why a
passing test suite is evidence about the tool the user actually runs.

The dependency arrow never points upward. `sanctum.core` does not import
`sanctum.erase`; no engine imports anything from `sanctum.gui`. This is what
makes the whole application usable without PyQt6 installed, and it is asserted
by `tests/test_gui.py::test_every_engine_module_imports_without_qt`.

---

## 2. The safety model

SANCTUM destroys data for a living, so the failure that matters is erasing
something that should have survived. The design assumes an operator who is
tired, in a hurry, and has several similar drives on the desk.

**Device targets require four independent conditions simultaneously:**

| Gate | Where it lives | Default |
|---|---|---|
| `SafetyPolicy.allow_raw_devices` | `sanctum/config.py` | `False` |
| `SANCTUM_ALLOW_RAW_DEVICE` | Process environment | unset |
| Typed confirmation token | `core/targets.py` | required |
| `SafetyPolicy.dry_run` off | `sanctum/config.py` | `dry_run=True` |

The token is `sha256(f"{path}|{size}|{serial}|{kind}")[:8].upper()`. Deriving it
from the device's own identity — not from a constant — means a token obtained
for one drive does not authorise a different drive that happens to be mounted at
the same letter. The operator has to look at the device and transcribe a value
that describes *it*.

Two refusals have no override at all:

- **The running operating-system drive.** The machine is running from it; a
  successful sanitization is a destroyed workstation. `_windows_system_drive()`
  and `is_system_path()` establish this, and `validate_for_erasure` refuses
  before any policy flag is consulted.
- **SANCTUM's own data directory.** Erasing the case store and audit chain would
  destroy the record of the erasure, which is a worse outcome than either alone.

**Two different notions of "system path", and why they must stay separate.**
`is_system_path()` is drive-letter based: `C:\Users\alice\notes.txt` is on the
system *drive* and is correctly refused as a **device** target. But the same
function would refuse to securely delete a file in the user's own Documents
folder, which is exactly what Module 2 is for. So file-tree operations use
`is_os_directory()` instead — containment within `C:\Windows`, `/usr`, `/etc`,
and similar OS-owned directories — plus `is_filesystem_root()`, which refuses
`C:\` or `/` because "securely delete the root of the filesystem" is never a
request with a good outcome.

Refusals are **audited**. A `SafetyViolation` writes a `DENIED` entry to the
chain before propagating. An attempt to erase a system drive is as visible in
the record as a completed erasure, which is what makes the safety system
reviewable after the fact rather than merely trusted.

---

## 3. Module 1 — drive sanitization

`DriveEraser.run(target, standard, *, policy, confirmation, verify, verify_mode,
progress, cancel, confirm)`:

1. Build the `EraseResult` skeleton, then run the policy gate
   (`validate_for_erasure`), then the confirmation gate.
2. Audit `drive_erase_started`.
3. If `policy.dry_run`, audit and return without writing a byte.
4. Otherwise, for each pass in `standard.effective_passes(verify)`:
   - write the pass pattern across the whole target via `TargetWriter`;
   - read it back through `verify_pass` according to `verify_mode`;
   - **a failed verification is a hard stop** — the loop breaks, `aborted` is
     set, and no further passes run. Continuing would overwrite the evidence
     that verification failed.
5. Audit `drive_erase_finished` with the outcome, and close the result's
   `audit_range`.

### The pattern-phase bug

This is the most interesting defect found during development, and it is worth
recording because it was invisible to every test that existed at the time.

A Gutmann pass writes the repeating 3-byte sequence `92 49 24`. The writer
works in 1 MiB chunks. **1 MiB is not a multiple of 3.** Writing the same 1 MiB
buffer repeatedly means that from the second chunk onward the media holds a
sequence that has been phase-shifted by one byte relative to the standard — so
the drive no longer contains the Gutmann pattern, while the report still claims
it does. Worse, verification made the identical assumption, so it compared the
media against the same wrong expectation and passed.

The fix is three methods on `PassSpec`:

- `period` — the length of the repeating unit (1 for ZERO/ONE/BYTE/RANDOM,
  `len(sequence)` for CYCLE).
- `aligned_size(requested)` — round the buffer down to a whole number of
  periods, so tiling it is phase-continuous.
- `expected_at(offset, length)` — the bytes the pattern should hold at an
  *absolute* offset, so verification windows that do not start on a period
  boundary are compared against the right phase.

`tests/test_standards.py::test_unaligned_tiling_would_break_phase` demonstrates
the bug the guard prevents; without it the guard could silently become a no-op.

### Media-type honesty

`_WARN_OVERWRITE_MEDIA = {SSD, NVME, USB_FLASH, SD_CARD}`. On these, an
overwrite does not produce the assurance the standard describes, because
wear-levelling and the flash translation layer decide where a write physically
lands. The blocks holding the original data may never be touched. The result
carries a warning naming the correct alternative (ATA SANITIZE / SECURITY ERASE
UNIT, NVMe Format/Sanitize, or TCG Opal crypto erase), and the warning reaches
the UI log and the report. On magnetic media, no such warning is emitted —
`test_flash_media_produces_a_wear_levelling_warning` and
`test_magnetic_media_produces_no_such_warning` pin both directions.

---

## 4. Module 2 — file and folder erasure

`FileEraser.secure_delete_file` performs, in order:

1. **Validate** the target (`_validate_file_target`): exists, is a file, is not
   inside SANCTUM's home, is not a filesystem root, is not an OS directory, is
   writable.
2. **Overwrite** the content in place for every effective pass, with the same
   phase-aligned chunking as Module 1.
3. **Cleanse the name** — rename to a random string of the same length,
   preserving the extension length, so the original name does not survive in
   the directory entry's slack.
4. **Truncate** to zero.
5. **Remove alternate data streams** on NTFS, where a file can carry hidden
   named streams that a content overwrite does not touch.
6. **Unlink.**
7. **Verify the post-condition** — the path must be gone.

`wipe_free_space` fills the volume's unallocated space with pattern files and
deletes them, which is the mechanism for destroying the residue of files that
were deleted before SANCTUM was ever involved. It is bounded by `max_bytes` and
emits warnings when it is about to consume a large fraction of a volume's free
space or when the target is an OS volume — filling the system drive to 98% while
a user is working is a real hazard, and it is stated before the run, not after.

### The batch accounting fix

A cancellation mid-batch used to produce a false record. `secure_delete_paths`
checks `cancel` at the top of its loop, so cancelling after 3 of 100 files left
`batch.results` holding 3 successful entries — and `failed == 0`, so the audit
entry recorded `SUCCESS` and the report said "3/3 removed". The operator asked
to destroy 100 files; the record said the job succeeded.

`FileEraseBatchResult` now carries `planned` (the number of targets requested,
which is not the same as `total`, the number attempted) and `cancelled`, plus a
`headline()` that names the shortfall: *"CANCELLED — 3/3 removed, ...; 97 of 100
path(s) were never attempted."* The audit outcome is `FAILURE` for a cancelled
batch, because a partial run does not meet the standard the operator asked for.

The same reasoning distinguishes a cancelled drive erase from an aborted one:
`EraseResult.cancelled` is separate from `aborted`, and `headline()` renders
them differently. A run stopped by the operator and a run stopped because
verification failed are opposite findings, and rendering both as "ABORTED"
invites the reader to assume the worse one.

---

## 5. Module 3 — carving and recovery

### Structural end-detection

The naive carving algorithm is *find header, find footer*. It fails on real
media, and it fails by producing a plausible-looking corrupt file.

The concrete case: **a JPEG's EXIF block commonly embeds a complete thumbnail
image, which has its own `FFD9` end-of-image marker.** A footer search stops at
the thumbnail's terminator and returns roughly the first few kilobytes of the
outer photo. The file opens in a viewer — often showing the thumbnail — so
nothing about the result announces that it is wrong.

SANCTUM determines the end structurally instead:

| Format | Method |
|---|---|
| JPEG | Walk the marker chain, reading each segment's declared length |
| PNG | Walk chunks to `IEND` |
| ZIP / Office | Locate the end-of-central-directory record and read the real size |
| PDF | Scan to the last `%%EOF` |
| BMP, RIFF, and others | Declared size in the header |

`tests/test_carver.py::test_embedded_thumbnail_does_not_truncate_the_jpeg`
constructs exactly the file described above and asserts the recovered length
exceeds the naive end offset. A carver that searches for footers fails it.

### Confidence scoring

Every artifact gets a score that is **the exact arithmetic sum of named,
individually-weighted factors**, all of which are retained in the output:

| Factor | Weight |
|---|---|
| Structural validation passed | +45 |
| Structural validation failed | −15 |
| Terminator found | +25 |
| Terminator missing (format has one) | −10 |
| Format has no terminator | +5 |
| Length plausible for the format | +15 |
| Below format minimum | −20 |
| Length at the size ceiling | −5 |
| Content near-constant, under 0.5 bits/byte, compressed format ("wiped or padding") | −45 |
| Content near-constant, under 0.5 bits/byte, uncompressed format | −25 |
| Entropy under 2.0 bits/byte for a format expected to be compressed | −8 |
| Entropy between 2.0 and 8.0 bits/byte | +10 |
| Truncated at the size ceiling | −12 |

Thresholds: High ≥ 80, Medium ≥ 55, else Low.

The point of retaining the factors is that a reviewer who disagrees with a
weighting can recompute the score, or reweight it, without re-running the scan.
`tests/test_classify.py::test_the_score_is_exactly_the_sum_of_its_factors` pins
the invariant; if it ever stops holding, the score becomes an opaque number and
the auditability claim is false.

The validated/not-validated asymmetry (+45 / −15) is the largest swing in the
table deliberately. A header match with nothing behind it is the dominant
false-positive mode in unallocated space, and this is the term that separates a
real find from a coincidental byte sequence.

### Fragmentation

`fragments.py` attempts to reassemble files whose extents are no longer
contiguous. This is genuinely hard, it does not always succeed, and the tool
says so: whenever reassembly was attempted, `reassembled` is set on the
operation and `LIMITATION_REASSEMBLY` is added to the report. The report
limitation list is computed from the operations actually performed, so a report
never pads itself with caveats about work it did not do.

### The optional native backend

`recover/native.py` wraps `pytsk3` and `pyewf` when present, exposing
filesystem-aware recovery: enumerate deleted entries with their original names
and timestamps, and compute the unallocated extents so a scan can be restricted
to them. When absent, `capabilities()` reports that cleanly and the pure-Python
carver — which works from content alone — handles everything. The Dashboard and
the Recovery page display which capabilities are live, so the operator always
knows which engine produced a result.

---

## 6. The audit chain

Each entry is a JSON object carrying `seq`, timestamp, actor, category, action,
target, detail, `prev_hash`, `hash` and `hmac`.

- `hash = sha256(canonical_json(entry without hash/hmac))`
- `prev_hash` = the previous entry's `hash`, giving a back-linked chain
- `hmac = HMAC-SHA256(key, canonical_json(entry without hmac))`

`verify()` walks the file and reports the first index at which any of these
fails: a modified field (hash mismatch), a forged entry without the key (HMAC
mismatch), a reordered pair (`prev_hash` discontinuity), a deleted entry
(sequence gap), and an unparseable line. `VerifyReport` carries `ok`,
`broken_at`, `reason` and `entry_count`.

**What it does not do.** It is tamper-*evident*, not tamper-*proof*. An attacker
who can rewrite the whole file can construct a shorter chain that verifies
perfectly from its own genesis; the tail loss is undetectable from the chain
alone. This limitation is pinned by a test and stated in every report. Claiming
otherwise would be the single most damaging thing this tool could do, because
the entire value of an audit record is that its guarantees are exactly what they
say they are.

---

## 7. Reporting

`ReportBuilder` accepts any object exposing `as_dict()` or a plain dict, so
every engine result is reportable without a translation layer.
`limitations()` inspects the operation kinds actually recorded and returns only
the caveats that apply:

| Operation kind | Limitations included |
|---|---|
| `drive_erase` | Overwrite is not a purge on flash |
| `file_erase`, `free_space_wipe` | Journal and copy-on-write residue |
| `file_carving` | Carving, confidence scoring |
| any with `reassembled` truthy | Reassembly |
| *always* | The audit chain is tamper-evident, not tamper-proof |

Three output formats: **HTML** for reading, **JSON** for machine consumption,
**CSV** for the artefact inventory (sorted by descending confidence, so the
reviewer's attention goes to the strongest evidence first).

**Every operator- and media-supplied string is HTML-escaped.** Case names,
examiner names, file paths, artefact names and notes all originate outside the
tool — from the operator and, more importantly, from the media under
examination. A carved artefact can carry a filename containing markup, and an
examiner opening a report about a suspect's drive must not execute the
suspect's script. `test_operator_supplied_text_cannot_inject_markup` asserts
that `<script>` does not survive into the HTML.

The report's central honesty property: when no audit chain is attached, the
integrity section says **"Audit chain not attached"** and the chain is reported
as `unverified` — never as intact. A broken chain says **"Audit chain BROKEN"**,
names the index, and states that the results cannot be relied upon. There is no
state in which a missing or damaged chain renders as a normal report.

---

## 8. Concurrency and cancellation

Every engine takes `progress: Callable[[ProgressUpdate], None]` and
`cancel: CancelToken` as keyword arguments. `CancelToken` wraps a
`threading.Event` and is *polled* at safe points; it never raises across
threads, because injecting an asynchronous exception into a thread that is
mid-write to a raw device leaves the target in an unknown state.

`ProgressReporter` throttles updates to `min_interval` (0.08 s) to stop a fast
loop from flooding the Qt event queue, but `start()` and `finish()` force an
emit so a phase transition is never lost to throttling.

The GUI runs each engine call on a `Job(QThread)`, which injects both. Signals
cross the thread boundary by Qt's queued connections, so the worker never
touches a widget. An engine exception is caught and delivered as a `failed`
signal with its traceback rather than killing the process — a traceback on a
worker thread with no handler takes the whole application down, which is
precisely the failure that would end a demonstration.

Engines deliberately convert cancellation into a **result** rather than
propagating it. A cancelled operation must still be recorded in the audit chain
and accounted for in the report; a raised exception would discard that record
along with the partial state it describes.

---

## 9. Test strategy

The generator in `tools/` is part of the test design, not a convenience.

**`tools/fat16.py` builds a spec-correct FAT16 image from scratch**, recording
each planted file's cluster chain and SHA-256 digest. That manifest is ground
truth: a recovered artifact either matches a planted file byte-for-byte or it
does not. This is what converts "the carver found 12 things" into "the carver
recovered 7 of 10 deleted files, byte-identical, with no false positives" — a
claim that can be checked, and that would be embarrassing to state without the
digest comparison behind it.

**`tools/sample_files.py` generates valid files with no third-party
dependency**, including a hand-written baseline JPEG encoder with spec-legal
custom Huffman tables. Using PIL would have been easier and would have made the
test suite's fixture supply depend on a package the tool itself does not need.

The suite is organised one module per subsystem
(`tests/test_standards.py`, `test_verify.py`, `test_erase_drive.py`,
`test_erase_file.py`, `test_carver.py`, `test_signatures.py`,
`test_classify.py`, `test_report.py`, `test_cases.py`, `test_audit.py`,
`test_hashing.py`, `test_safety.py`, `test_gui.py`, plus `conftest.py`).

Two habits are worth noting, because they are the ones that found real bugs:

- **Tests that would fail a plausible wrong implementation.** The
  embedded-thumbnail JPEG, the unaligned tiling check, the score-is-the-sum
  invariant, the short-read mismatch. Each is written against a specific way the
  code could be wrong, not against the way it happens to be written.
- **`conftest.py` redirects `SANCTUM_HOME` to a temporary directory before any
  `sanctum` module is imported**, because `sanctum.config` resolves its paths at
  import time. A test run must never write into the developer's real case store.
