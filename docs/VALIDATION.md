# SANCTUM — Validation & Testing

This document describes how SANCTUM is tested, what the tests actually
establish, and — with equal importance — what they do not.

---

## 1. How to run the suite

```bash
pip install pytest
python -m pytest tests -q
```

`python -m pytest` is specified rather than bare `pytest` because the `-m` form
puts the working directory on `sys.path`, which is what makes `from tools...`
and `from sanctum...` resolve. `tests/conftest.py` also inserts the project root
explicitly, so either invocation works — but the documented one is the one that
was intended.

To see the measured recovery accuracy reported, run:

```bash
python -m pytest tests/test_carver.py -q -s
```

The accuracy test prints a recall/precision table against the build manifest.

---

## 2. Test organisation

| Module | Subsystem under test |
|---|---|
| `conftest.py` | Shared fixtures; redirects `SANCTUM_HOME` before any import |
| `test_hashing.py` | Digests, streaming hashes, Shannon entropy, `human_bytes` |
| `test_audit.py` | Chain construction, sealing, and every tamper-detection path |
| `test_safety.py` | Policy gates, token derivation, refusals, audited denials |
| `test_standards.py` | The 9 standards: pass counts, patterns, phase arithmetic |
| `test_verify.py` | Read-back verification: full, sampled, short reads |
| `test_erase_drive.py` | Module 1 end to end, including abort and cancellation |
| `test_erase_file.py` | Module 2: overwrite ordering, metadata, batches, sweeps |
| `test_carver.py` | Module 3: structural detection, extraction, accuracy |
| `test_signatures.py` | Signature registry and every structural validator |
| `test_classify.py` | Confidence scoring and the factor-sum invariant |
| `test_report.py` | HTML/JSON/CSV, conditional limitations, escaping |
| `test_cases.py` | Cases, evidence register, chain continuity, containment |
| `test_gui.py` | Page construction, worker threads, widget behaviour, table sorting and selection |

`test_gui.py` calls `pytest.importorskip("PyQt6")` at module scope and skips
cleanly when the GUI dependency is absent. The tool is required to work without
it, so a machine that cannot run the GUI tests can still validate every engine.

The suite is run with `QT_QPA_PLATFORM=offscreen`, so it needs no display. The
interface was additionally launched against the real Windows platform plugin —
`app.platformName() == "windows"`, all eight pages constructed and shown — to
confirm the offscreen runs were not passing for a reason specific to the
offscreen backend.

Constructing a widget is not the same as using one, so the suite also drives a
real carve end to end: `test_a_carve_runs_through_the_recovery_view_and_reaches_the_table`
sets the source, presses the button, waits for the worker, and asserts the
artefacts reached the table and that selecting one renders its confidence
derivation. Widget construction alone did not catch the selection defect
recorded in §4.10 — the table rendered eleven rows perfectly and refused to show
any of them.

---

## 3. The approach: ground truth, not plausible output

The single most important design decision in this suite is that **fixtures are
generated and measured, not asserted from memory.**

`tools/fat16.py` builds a FAT16 filesystem image from scratch — boot sector,
two FATs, root directory, cluster chains — and records, for every planted file,
its size, its cluster chain and its SHA-256 digest. `tools/make_test_media.py`
uses it to produce a 16 MiB image containing ten deleted files and two live
ones, plus a fragmented-files image, a pre-wiped image and a blank scratch
image.

That manifest is what lets the accuracy test make a falsifiable claim:

> The carver recovered 7 of the 10 deleted files, byte-identical by SHA-256,
> with zero false positives at High confidence.

A test that instead asserted `result.recovered_count > 0` would pass for a
carver that returns garbage, and would pass for a carver that fabricates files.
The digest comparison cannot be satisfied by either.

`test_deleted_files_are_found_in_unallocated_space` adds the converse guard: it
asserts that no deleted file's bytes are present in *allocated* space. If the
FAT16 builder were ever changed such that "deleted" files remained allocated,
the recovery test would start passing for the wrong reason — this test fails
instead.

---

## 4. Tests written to fail a plausible wrong implementation

These are the highest-value tests in the suite, because each is aimed at a
specific way the code could be wrong rather than at the way it happens to be
written.

### 4.1 The embedded thumbnail

```python
def test_embedded_thumbnail_does_not_truncate_the_jpeg(tmp_path):
    crafted, naive_end = _jpeg_with_embedded_thumbnail()
    ...
    assert artifact.length == len(crafted)
    assert artifact.digests["sha256"] == _sha256(crafted)
    assert artifact.length > naive_end
```

The fixture builds a JPEG whose EXIF segment embeds a complete second JPEG,
with its own `FFD9` marker. A carver that finds the first footer and stops
recovers `naive_end` bytes of the outer image. The test asserts the recovered
length is the full outer file. This is the clearest example in the project of a
test that distinguishes a real implementation from a demo.

### 4.2 The pattern-phase guard

```python
def test_unaligned_tiling_would_break_phase():
    """Confirms the guard above is testing something real."""
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    unaligned = spec.build_buffer(1048576)
    assert (unaligned + unaligned) != spec.build_buffer(len(unaligned) * 2)
```

and its counterpart in the erasure engine,
`test_cycling_pattern_stays_in_phase_across_chunk_boundaries`, which writes
`CHUNK_SIZE + 5000` bytes and compares the media against one continuous pattern
buffer.

Together these pin a bug that was real, silent, and compliance-relevant:
`CHUNK_SIZE` is 1 MiB, which is not a multiple of the Gutmann 3-byte sequence,
so per-chunk tiling shifts the pattern's phase after the first megabyte. The
media would no longer contain the standard's pattern while the report claimed
it did — and verification made the same wrong assumption, so it could not
catch it. The second test exists so that the first cannot quietly become
vacuous.

### 4.3 The score-is-the-sum invariant

```python
def test_the_score_is_exactly_the_sum_of_its_factors(signature, probe):
    for case in cases:
        result = score_artifact(signature, probe, **case)
        assert result.confidence == max(0.0, min(100.0, sum(f.weight for f in result.factors)))
```

The confidence score's justification is that a reviewer can recompute it from
the retained factors. That claim is either true or the score is an opaque
number wearing a lab coat. This test decides which.

### 4.4 The short read

```python
def test_a_short_read_is_a_mismatch_not_a_pass(...):
```

A verification window that returns fewer bytes than requested must be recorded
as a mismatch. Comparing only the bytes that did arrive would let a truncated
read — or a device that silently stops returning data — pass as verified, which
is precisely the failure mode verification exists to catch.

### 4.5 Markup injection through examined media

```python
def test_operator_supplied_text_cannot_inject_markup():
    payload = '<script>alert("xss")</script>'
    ...
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
```

Filenames come from the media under examination. An examiner opening a report
about a suspect's drive must not execute the suspect's script. This is a
security property of the tool, tested as one.

### 4.6 A PDF must not run into the next PDF

```python
def test_a_pdf_is_not_extended_into_the_next_document(tmp_path):
    first  = make_pdf("First Report",  "The first document's body. " * 40)
    second = make_pdf("Second Report", "The second document's body. " * 40)
    source.write_bytes(first + b"\x00" * 8192 + second)
    ...
    assert _sha256(first) in digests
    assert _sha256(first + gap + second) not in digests
```

This test exists because the obvious version of it does not work. With a single
PDF in the image, "the first `%%EOF`" and "the last `%%EOF`" are the same
offset, so `test_pdf_is_recovered_through_its_trailer` passes for an engine that
takes the last one. The PDF signature's search ceiling is 256 MiB; with a second
document present, a last-`%%EOF` search runs the first artefact forward until it
swallows the second, yielding one blob with a valid header, a valid structure,
and a digest matching neither file — reported at high confidence. Over-running
is silent and catastrophic; stopping early is visible and bounded. Only a
two-document fixture separates the two behaviours, so that is what the test
builds.

### 4.7 A multi-pass free-space sweep must do more than one pass

```python
def test_a_multi_pass_sweep_overwrites_the_space_once_per_pass(tmp_path, eraser, safe_policy):
    budget = 256 * 1024
    result = eraser.wipe_free_space(tmp_path, "dod3", policy=safe_policy, max_bytes=budget)
    assert result.passes_executed == 3
    assert result.bytes_written >= 3 * budget
```

A free-space sweep works by consuming the volume's free space. If a pass leaves
its filler files on disk, the volume is already full when the next pass begins,
so passes 2..*n* write nothing — while the result still reports
`passes_executed: 3`. The assertion is therefore against the number of passes
rather than against zero, because zero is what a broken sweep produces and
"greater than zero" is satisfied by one effective pass wearing three passes'
worth of claims. The companion test,
`test_the_sweep_fills_with_many_files_not_one_enormous_one`, lowers the per-file
bound and asserts the fill is split across files: one filler file large enough
to fill a volume would exceed FAT32's 4 GiB per-file ceiling, which is exactly
where a USB stick — this module's most likely target — would stop part-way and
still report success.

### 4.8 A header is not a file

The clearest failure this tool can produce is Module 3 reporting files
recovered from Module 1's output. A sanitized volume's final pass is random
data, and random data contains magic numbers: a two- or three-byte header
occurs roughly a quarter of a million times per gigabyte, so a validator that
stops at the magic manufactures phantom "recovered" files out of a
successfully wiped drive.

Four formats were in that state — MP3, BMP, gzip and bzip2 — and each is now
validated against structure immediately behind the magic:

| format | what was checked | what is checked now |
|---|---|---|
| MP3 | 4 header bytes, ~11 constrained bits | a second frame header landing at exactly the offset the first implies |
| BMP | `BM` plus a wide declared-size range | full DIB header, cross-field consistency, non-zero dimensions, plane count, bit depth, pixel-offset bounds |
| gzip | `\x1f\x8b\x08` | reserved flag bits, XFL, OS code, optional-field parsing, deflate block type |
| bzip2 | `BZh` | compression level digit, then the block constant |

The MP3 case is the sharpest, because its header is small enough that roughly
one random window in 370 matches. The test asserts against a *near miss* — a
second header correct in every field but at the wrong stride — because that,
and not obvious junk, is what random data produces:

```python
header = real[:4]
wrong_stride = header + b"\x00" * 296 + header + b"\x00" * 2000
assert validate_mp3(wrong_stride) is False
```

The end-to-end consequence is measured, not asserted: the self-test reports
`no fabricated high-confidence artefacts - 0 phantom(s)` against a wiped image.

### 4.9 Truncation is not invalidity

`validate_jpeg` walked the marker chain and returned `False` when the data ran
out. That conflated "this is not a JPEG" with "this JPEG is incomplete" — and
incomplete is what a JPEG recovered from damaged media *is*. The effect was
that the engine's entire truncation-reporting path, which exists to tell an
examiner a file is partial, was unreachable for every format with a structural
validator: being incomplete was the thing that made them fail validation.

The two are now separate. A malformed chain means it is not a JPEG; a
well-formed chain that ends because the data ends means it is a JPEG and the
end-detection layer reports the truncation through its own `truncated` flag.

A second defect sat behind the first: `min_size` rejected the same files. The
floor asks "could this be a whole file of this format?", and a truncated
artefact is smaller than that by definition — so for a truncated candidate the
floor drops to twice the format's header length, which is enough to still
exclude a bare magic number with nothing behind it.

### 4.10 A table that looks sorted and is not

The results table set each cell's numeric sort key with
`setData(DisplayRole, value)` and then called `setText(...)`. `setText` writes
the DisplayRole, so it overwrote the key that had just been stored: the cells
displayed `0x1000` and sorted as the string `"0x1000"`, in which `"0x200"` is
larger. The header arrow claimed a sort the table was not performing.

The same overwrite broke the detail pane. Selecting a row looked the artefact
up by comparing `artifact.offset` — an integer — against the cell's data, which
was by then the string. Nothing ever matched, so the confidence derivation
never appeared no matter what was clicked. Both are now keyed on a value
`setText` cannot reach, and both are pinned:

```python
def test_selecting_a_sorted_row_shows_that_artefacts_derivation(qapp):
    ...
    view.table.sortItems(0, Qt.SortOrder.DescendingOrder)
    view.table.selectRow(0)
    assert "second.jpg" in view.explanation.toPlainText()
```

Writing that test surfaced a third problem in the same area. Switching sorting
on applies whatever the header indicator says, and Qt's default is column 0
**descending** — so the results opened in reverse filename order, agreeing with
neither the engine's ranking nor scan order. The initial order is now the
carver's own (ascending offset, the order the media was scanned), which is
asserted directly:

```python
assert header.sortIndicatorSection() == 2
assert header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
```

The audit view had the same defect in its `Seq` column, and there the
consequence was worse. Inspecting the mechanism showed why the obvious fix does
not work: constructing an item with a string and *then* overwriting
`DisplayRole` with an integer leaves it sorting as text, and only setting
`DisplayRole` to an integer with no prior string construction sorts numerically.

| construction | order produced |
|---|---|
| `QTableWidgetItem(str(seq))` then `setData(DisplayRole, seq)` | `1, 10, 100, 11, 2, 9` |
| `setData(DisplayRole, seq)` alone | `1, 2, 9, 10, 11, 100` |
| `setData(DisplayRole, seq)` on an item also given display text | `1, 10, 100, 11, 2, 9` |

The audit view used the first form, so a chain of ten or more records displayed
in the order `1, 10, 11, 12, 2, 3…` — a list in no order, in the one view whose
entire subject is the order the records were written in. Both tables now use one
mechanism, `NumericItem`, which keeps the sort key in a role that setting the
display text cannot reach and overrides the comparison. The audit view's initial
order is now chain order, which is the order `verify` walks and the order the
sequence numbers mean.

### 4.11 A measurement that measured noise

The performance harness reported SAMPLE verification costing 1.64× an
unverified write and FULL costing 1.29× — that is, reading a quarter of the
media as dearer than reading all of it. The engine is not at fault: measured
directly, reading 64 MiB in 64 strided windows takes 0.23× the time of reading
256 MiB sequentially.

The harness was. Each sample is one whole write of the target plus the
read-back, so the measurement is dominated by the write, and the write varies
by about a third between runs on this machine. Over three samples the median
lands wherever the disk happened to be; over seven, the ordering is the one the
hardware has:

| samples | none | sample | full |
|---|---|---|---|
| 3 | 1.00 | **1.64** | 1.29 |
| 7 | 1.00 | 1.02 | 1.24 |

The verification section is cheap next to the erase and carve sections, so it
now takes a floor of seven samples regardless of `--repeats`. The companion
defect was `bytes_read_back: None` for SAMPLE — the one mode whose cost is
least obvious was the one mode with no byte count attached — which now comes
from the engine's own accounting rather than being recomputed in the harness,
so the report describes the run instead of the harness's expectation of it.

---

## 5. Safety validation

The safety system is validated in the direction that matters: proving it
refuses.

| Property | Test |
|---|---|
| Raw devices refused without the policy flag | `test_safety.py` |
| Raw devices refused without the environment key | `test_safety.py` |
| Confirmation token derived from device identity | `test_safety.py` |
| Wrong token refused | `test_erase_drive.py`, `test_safety.py` |
| OS drive refused unconditionally | `test_safety.py` |
| SANCTUM's own data directory refused | `test_erase_drive.py`, `test_erase_file.py` |
| Filesystem root refused as a file target | `test_erase_file.py` |
| OS directory refused as a file target | `test_erase_file.py` |
| Refusal is recorded in the audit chain as DENIED | `test_erase_drive.py`, `test_erase_file.py` |
| Dry run writes nothing | `test_erase_drive.py`, `test_erase_file.py` |

Two notes on method:

**The OS-directory test does not write into a real OS directory.** An earlier
version attempted to create a file under `C:\Windows`, which needs elevation and
would have risked a real deletion had the guard failed. It now monkeypatches
`is_os_directory` to return `True`. As the test's own comment puts it: *a test
that only passes because the guard works is not worth the risk of it not
working.*

**Containment is tested with a traversal attempt.**
`test_delete_refuses_a_path_outside_the_cases_directory` passes both
`"../unrelated"` and an absolute outside path to `CaseManager.delete` and
asserts the outsider directory survives.

---

## 6. Failure-path validation

Happy paths are the easy half. These cover things going wrong:

| Failure | Expected behaviour | Test |
|---|---|---|
| Verification fails mid-run | Hard stop before the next pass; evidence of failure preserved | `test_a_failed_verification_aborts_before_the_next_pass` |
| Engine raises unexpectedly | Becomes `result.error`, not a crash | `test_an_unexpected_engine_error_becomes_a_result_not_a_crash` |
| Target does not exist | Refused | `test_a_nonexistent_target_is_refused` |
| Target is read-only | Refused | `test_a_read_only_target_is_refused` |
| Cancellation mid-erase | `aborted` and `cancelled` set, partially-written state recorded | `test_erase_drive.py` |
| Cancellation mid-batch | Batch marked `cancelled`, un-attempted paths counted | `test_erase_file.py` |
| Partial batch failure | Failures counted and reported individually | `test_erase_file.py` |
| Carver source missing | `result.error` set, no exception | `test_carver.py` |
| No signatures selected | `"No signatures selected"` | `test_carver.py` |
| Corrupt case directory | Skipped; other cases still listed | `test_list_cases_skips_a_corrupt_case_directory` |
| Client-side artifact limit | Capped at `max_artifacts` | `test_carver.py` |
| GUI worker raises | Delivered as a message, application survives | `test_a_failing_job_reports_the_error_instead_of_crashing` |
| A second PDF follows the first | The first stops at its own `%%EOF`, not the later one | `test_a_pdf_is_not_extended_into_the_next_document` |
| Sweep pass leaves its fillers behind | Each pass writes the full budget | `test_a_multi_pass_sweep_overwrites_the_space_once_per_pass` |
| Sweep target is FAT32 | Fill is split across files, none near the 4 GiB ceiling | `test_the_sweep_fills_with_many_files_not_one_enormous_one` |

---

## 7. Audit chain validation

Each detection path is tested by constructing the tamper and asserting it is
caught:

- **Modification** — rewrite a field in a sealed entry → hash mismatch.
- **Forgery** — insert an entry without the HMAC key → HMAC mismatch.
- **Reordering** — swap two entries → `prev_hash` discontinuity.
- **Deletion** — remove an entry → sequence gap.
- **Corruption** — write an unparseable line → parse failure with an index.
- **Continuity across sessions** — close and reopen a case; the next entry's
  `seq` continues and the chain still verifies.

And the report's handling of each: an intact chain renders as intact; a broken
chain renders "Audit chain BROKEN", names the index, and states the results
cannot be relied upon; **an unattached chain renders as `unverified`, never as
intact.** That last one is the property most worth having a test for.

### The documented limitation

A truncated chain's tail loss is undetectable from the chain alone — an attacker
who rewrites the whole file can produce a shorter chain that verifies from its
own genesis. This is pinned by a test and stated in every report. It is recorded
here as a **known and accepted limitation**, not a defect awaiting a fix: a
hash chain cannot detect its own truncation without an external anchor, and
claiming otherwise would be the most damaging thing this tool could do.

---

## 8. Interface validation

`test_gui.py` runs headless (`QT_QPA_PLATFORM=offscreen`) and checks the
failures that are invisible to every other module and fatal to a demonstration:

- Every engine module imports without PyQt6 — the GUI is genuinely optional.
- Every page constructs and opens (`window.nav.count() == len(_NAVIGATION)`,
  and each row's `currentIndex()` matches). A typo in one view's `refresh()`
  path is invisible until someone clicks that tab, which is exactly when a demo
  is being given.
- A worker `Job` delivers results, reports progress, reports failures as
  messages rather than crashes, and can be cancelled.
- A carve runs through `RecoveryView` and its artefacts reach the table, with a
  selected row rendering its confidence derivation (§4.10).
- The results table sorts offsets and lengths numerically, and a selected row
  maps back to the artefact it displays after the sort has permuted the rows.
- The audit table orders the chain by sequence numerically, and opens in chain
  order (§4.10).
- The drive-erasure confirmation states the exact bytes to be written
  (`size × passes`) before the token is typed, since the pass count is the whole
  cost model and it is chosen from a dropdown.
- `LogPane` escapes markup and caps its history.
- `ProgressPanel` handles determinate and indeterminate updates without
  dividing by zero.
- The default policy is `dry_run=True`.

---

## 9. What these tests do not establish

Stated plainly, because a validation document that only lists successes is not
a validation document.

1. **No test has been run against real hardware.** Every erasure test operates
   on a disk image. Whether a specific SSD honours an ATA SANITIZE command, or
   a specific USB bridge passes it through, is a property of that device and is
   not testable from here. The tool warns about exactly this on flash media
   rather than implying it has been verified.

2. **Recovery accuracy is measured on synthetic FAT16 media.** Real cases
   involve NTFS, ext4, APFS, fragmented files, partially-overwritten extents,
   and drives that have been in use for years. The synthetic corpus establishes
   that the carving engine works correctly on known ground truth; it does not
   establish a recall rate for any real-world filesystem.

3. **The confidence thresholds are calibrated by judgement, not by a labelled
   corpus.** 80 and 55 are defensible choices informed by the weights, but they
   have not been fitted against a large set of examiner-labelled results. A
   deployment should treat them as tunable and validate them against its own
   material.

4. **The optional native backend is not exercised when pytsk3 is absent.**
   Those code paths require the library; where it is not installed they are
   untested as well as unused.

5. **Fragmented-file reassembly is best-effort.** The fragmented fixture
   exercises the mechanism, but reassembly of arbitrary real-world
   fragmentation is an open problem in the field and is not claimed here.

6. **A PDF written with incremental updates is recovered to its first
   revision.** The carver terminates a PDF at the first `%%EOF` at or after the
   header, which is also what foremost and scalpel do. A document saved
   repeatedly carries one `%%EOF` per revision, and the carver returns the
   first. The alternative — searching for the last `%%EOF` in a 256 MiB window —
   merges neighbouring documents, which is a far worse failure, so the
   conservative rule is the deliberate choice. Distinguishing a revision
   boundary from a neighbouring file's trailer needs the document's true extent
   on both sides, which is the very thing carving does not have.
   `tools/make_test_media` writes single-revision PDFs, so the fixture does not
   exercise this either way.

7. **The free-space sweep cannot sanitize slack space or journals.** It
   overwrites unallocated clusters. Bytes inside an existing file's slack, and
   filename fragments retained in NTFS `$UsnJrnl`/`$LogFile`/MFT or the ext3/4
   journal, are outside user-space reach. The tool states this in the result,
   the report and the manual rather than implying the sweep is complete.

---

## 10. Reproducing the results

```bash
# 1. Everything, headless
python run.py --selftest

# 2. The full suite
python -m pytest tests -q

# 3. Just the recovery accuracy measurement, with its printed report
python -m pytest tests/test_carver.py -q -s

# 4. Performance figures on this machine
python -m tools.benchmark --quick      # indicative
python -m tools.benchmark              # full measurement
```

`--selftest` prints what it measured on the machine it ran on, including recall
against SHA-256 ground truth and whether tampering with the audit log was
detected. It is the fastest way to establish the actual state of an
installation.
