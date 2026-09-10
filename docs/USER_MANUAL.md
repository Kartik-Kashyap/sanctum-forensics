# SANCTUM — User Manual

Integrated Secure Data Erasure & Forensic Recovery Platform

---

## Contents

1. [Installing and starting](#1-installing-and-starting)
2. [The screen layout](#2-the-screen-layout)
3. [A first run that cannot destroy anything](#3-a-first-run-that-cannot-destroy-anything)
4. [Working with cases](#4-working-with-cases)
5. [Module 1 — Secure Drive Eraser](#5-module-1--secure-drive-eraser)
6. [Module 2 — Secure File & Folder Eraser](#6-module-2--secure-file--folder-eraser)
7. [Module 3 — Advanced File Carving & Recovery](#7-module-3--advanced-file-carving--recovery)
8. [Reports](#8-reports)
9. [The audit chain](#9-the-audit-chain)
10. [Settings and the safety interlocks](#10-settings-and-the-safety-interlocks)
11. [Command line](#11-command-line)
12. [Troubleshooting](#12-troubleshooting)
13. [Glossary](#13-glossary)

---

## 1. Installing and starting

### Requirements

| Component | Required? | Notes |
|---|---|---|
| Python 3.11 or newer | **Yes** | Checked on 3.11 and 3.13 |
| PyQt6 | For the interface | The engines and the command line work without it |
| pytsk3, pyewf | Optional | Filesystem-aware recovery and EnCase `E01` images |
| pytest | Only for the test suite | |

The three engines, the audit chain and the report writer use **no third-party
libraries at all**. If PyQt6 will not install on a machine, everything except
the interface still works.

### Install

```bash
cd SIH2026-forensic1
pip install PyQt6
```

Nothing else is needed. The project runs from its own directory without being
installed into the Python environment.

### Verify before you trust it

```bash
python run.py --selftest
```

This builds synthetic evidence images, runs all three modules against them,
measures recovery against recorded SHA-256 digests, checks that the audit chain
detects tampering, and prints a PASS/FAIL summary. **Run this first.** It is
the only claim about a given machine that is worth anything, and it takes a
minute.

### Start the application

```bash
python run.py
```

---

## 2. The screen layout

The window has three parts.

**The sidebar** on the left lists the eight pages in workflow order — look,
then act, then account for it:

| Page | Purpose |
|---|---|
| Dashboard | Session overview, capabilities, integrity status |
| Drive Eraser | Sanitize a whole device or disk image |
| File Eraser | Selective secure deletion and free-space sweeping |
| Recovery | Carve and recover files from damaged media |
| Reports | Generate the report and audit record |
| Audit | Browse and verify the tamper-evident chain |
| Cases | Cases, evidence register, chain of custody |
| Settings | Safety policy and runtime configuration |

**The status bar** along the bottom is not decoration. It carries two facts
that change what the tool will let you do:

- the **current case**, in amber when none is open and green when one is;
- the **policy state** — whether dry run is on, whether raw devices are
  disabled, locked by the environment, or armed, and how many operations this
  session has performed.

**The page area** changes as you navigate. Each page reports its results in a
scrolling log pane, and long operations show a progress panel with a **Cancel**
button.

> **Pages refresh when you open them.** If you leave a page and come back, it
> re-reads the current state rather than showing you what was true when you
> last looked.

---

## 3. A first run that cannot destroy anything

SANCTUM ships in a configuration that **cannot write to anything**. This is not
a tutorial caveat; it is the default state of the policy, and it is worth
walking through once so you know what "armed" looks like later.

1. Start the application and stay on the **Dashboard**. Read the *Capabilities*
   card: it tells you whether the native backend (pytsk3/pyewf) is present. If
   it is not, recovery still works — it just cannot restrict a scan to
   unallocated space.
2. Go to **Drive Eraser**. Notice that **Start erasure** is disabled until you
   select a target. Select a disk image with **Browse image...**.
3. Look at the status bar: `Dry run: ON`, `Raw devices: disabled`.
4. Press **Start erasure**. It runs the full plan, writes a complete audit
   record, and reports: *"Dry run — no data was written"*. The image on disk is
   untouched. That is the mode to demonstrate first.

When you are ready to write for real, you turn dry run off — see
[§10](#10-settings-and-the-safety-interlocks).

---

## 4. Working with cases

A **case** groups operations, evidence and audit records under one identity.
You can work without one, but a report is much weaker without it: the chain of
custody has nothing to hang from.

### Create a case

1. Open **Cases**.
2. In the **New case** card, fill in:
   - **Name** — e.g. `Operation Falcon`
   - **Examiner** — the person accountable for the work
   - **Description** — scope and, importantly, *authorisation notes*
3. Press **Create case**.

The case now appears under **Cases on this system** and its name shows in the
status bar.

### Register evidence

The evidence register is a list of items with their digests, recorded at the
moment of acquisition.

1. With a case open, press **Register evidence...** and choose the item — an
   image file, a device, a directory.
2. SANCTUM hashes it and records the digest, size, and time.
3. Later, press **Re-hash and compare** to verify the item has not changed.
   A mismatch is reported prominently: it means either the evidence or the
   record has been altered, and both possibilities matter.

> **Hash the evidence before you work on it, not after.** The register is only
> meaningful as a before-and-after comparison.

### Close a case

**Close case** saves and releases it. The audit chain is sealed and the case
directory can be archived as one unit.

---

## 5. Module 1 — Secure Drive Eraser

Sanitizes an entire device or disk image to a recognised overwrite standard,
with per-pass read-back verification and a sealed audit record.

### Choosing a target

**Target kind** offers two options:

**Disk image file** — a `.img`, `.dd`, `.raw` or `.iso` file. This is the
default working mode and needs no special privileges. Use it for
demonstrations, for testing, and for sanitizing a copy of media rather than the
original.

**Physical device** — real hardware. Selecting this switches the panel to a
device list populated by **Rescan devices**. Devices that need elevation are
labelled `- needs elevation`. This mode is gated by the interlocks in §10; if
they are not satisfied, the engine refuses the operation and records the
refusal in the audit chain.

### Reading the media warning

Once a target is selected, a warning appears if the media type is flash-based
(SSD, NVMe, USB flash, SD card):

> *"SSD media uses wear-levelling and block remapping. An overwrite is NOT a
> guaranteed purge on this device — the controller may retain previous physical
> pages. The firmware sanitize command (ATA SANITIZE, NVMe Format/Sanitize, TCG
> Opal crypto erase) is the correct instrument for this media."*

**Take this seriously.** On flash, overwriting is the wrong instrument, and a
report that says "verified" about an SSD overwrite is misleading. SANCTUM
shows this warning *before* the operation, and repeats it in the report, so
that nobody has to remember it later.

On magnetic media (HDD) no such warning appears, because there an overwrite is
a genuine purge.

### Choosing a standard

The **Standard** dropdown lists nine schemes with their pass counts. The detail
text below it shows the description, compliance references, intended use, and
whether verification is on by default.

The pass count is the whole cost model, so the Confirmation card states the
consequence in bytes before you commit. Selecting Gutmann on a 1 TB drive shows:

> Will write 31.83 TB over 35 passes across 931.32 GB of media (35x the target).

A standard writes a multiple of the target's size equal to its number of passes.
That figure is exact — size times passes, not an estimate — and on this drive it
is the difference between roughly half an hour under Single Pass Zeros and
roughly nineteen hours under Gutmann. No time estimate is shown: a duration
would have to assume a sustained rate on a device the tool has not measured, and
a confidently wrong "about 40 minutes" in front of a day-long operation is worse
than no estimate at all. §7 of the performance evaluation gives the measured
rates if you want to work the number out yourself.

These are the exact names as they appear in the dropdown:

| Standard | Passes | Notes |
|---|---|---|
| Single Pass Zeros | 1 | Fastest; suitable when the threat model is casual recovery |
| Single Pass Random | 1 | Non-predictable content; the default for free-space sweeps |
| NIST SP 800-88 Purge (overwrite profile) | 3 | Follows the NIST purge guidance |
| DoD 5220.22-M (3-pass) | 3 | Widely cited; write-verify per pass |
| DoD 5220.22-M ECE (7-pass) | 7 | The extended variant |
| Schneier (7-pass) | 7 | Schneier's published scheme |
| VSITR (7-pass) | 7 | Russian standard, 7 passes |
| HMG Infosec Standard 5 - Enhanced | 3 | UK government guidance |
| Gutmann (35-pass) | 35 | The full 35-pass scheme; slow, and rarely justified today |

All nine carry `recommended_for = HDD`. That is the tool's own statement that
none of them is the right instrument for flash media — see the media warning
above.

If you are unsure, **DoD 5220.22-M (3 pass)** is a defensible default for
magnetic media: it is recognised, it is quick enough to run on real hardware,
and its pass structure is easy to explain to a reviewer.

> **More passes is not automatically better.** For modern magnetic drives a
> single pass is very often sufficient. Gutmann's 35 passes were designed for
> drive technologies that no longer exist. Choose the standard you can justify,
> and let the report record which one you chose.

### Choosing verification

| Mode | What it does | Cost |
|---|---|---|
| Sampled (64 windows) | Re-reads 64 evenly-spread 1 MiB windows, including the first and last | Low |
| Full (byte-for-byte) | Re-reads and compares every byte | Roughly doubles or triples the time |
| None | Reports `unverified` | None |

**Sampled** is a good default. It catches a device that stopped accepting
writes, a controller that silently discarded a region, or a pass that was
skipped — the failures that actually happen. **Full** is worth its cost when
the drive is small or the operation is the entire point of the engagement.

Choosing **None** is not a way to hide a failure: the result records
`unverified`, and `unverified` is deliberately a *different value* from
`failed`. A report that could not tell "not checked" from "checked and failed"
would be worse than useless.

If a verification **fails**, the run stops immediately rather than continuing
to the next pass. Continuing would overwrite the evidence of the failure.

### Running it

1. Set the policy (dry run off, and the raw-device interlocks if you are using
   real hardware).
2. Type the **confirmation token** shown in the Confirmation card. It is
   derived from the target's path, size and serial — a token shown for one
   device will never validate for another.
3. Press **Start erasure**.
4. Confirm the warning dialog. It restates the device name, path and size, and
   says plainly that the operation cannot be undone.
5. Watch the pass table fill in. Columns: **Pass**, **Pattern**, **Bytes
   written**, **Duration**, **Verification**.

### Reading the result

The headline is the summary, and it distinguishes states that matter:

| Headline | Meaning |
|---|---|
| `Dry run — no data was written` | Nothing was touched |
| `CANCELLED by operator — target is partially written` | You stopped it; earlier passes did complete |
| `ABORTED` | Verification failed and the run stopped |
| `FAILED` | An error occurred |
| `... — unverified` | Completed, but no verification was requested |
| Normal summary | Completed and verified |

A cancellation and a verification failure are reported as **separate**
findings on purpose. They are opposite results, and collapsing them into one
word invites a reader to assume the worse one.

### Cancelling

**Cancel** requests a stop. The engine stops at its next safe point — it does
not abandon a partially-written block. The audit chain records the
interruption, and the result carries a warning that the target does not meet
the selected standard and must not be reported as if it did.

---

## 6. Module 2 — Secure File & Folder Eraser

Two operations on one screen, because they attack the same problem from
opposite directions.

### Selective deletion

Overwrites named files in place, renames their directory entries to
uninformative names of the same length, and unlinks them.

**Steps:**

1. Under **Selection**, press **Add files...** or **Add folder...**. Selected
   paths appear in the list. `Remove` and `Clear` manage the list.
2. Under **Standard and options**, choose the overwrite standard. **DoD
   5220.22-M (3 pass)** is the default.
3. Decide on:
   - **Cleanse metadata** (on by default) — renames the entry to an
     uninformative name of matching length, truncates the file before
     overwrite, and removes alternate data streams. This is what removes the
     *name*, not just the content.
   - **Recurse into subfolders** (on by default).
   - **Dry run** (on by default) — turn this off to actually delete.
4. Type `DELETE` in the Confirmation box. A word is used here rather than a
   derived token because the risk in this operation is misjudging *which files
   were selected*, not which device — so the speed bump should name the action.
5. Press **Delete selected paths**.

**Read the limitation notice before you rely on this.** Filesystem journals and
table records — NTFS `$UsnJrnl`, `$LogFile`, the MFT; the ext3/4 journal — may
retain filename and timestamp fragments that user-space code cannot reach. A
rename reduces this; it does not eliminate it. **Only whole-media sanitization
removes it.** If that distinction matters to your case, delete the files and
then sanitize the whole volume.

### Free-space sweep

Attacks what selective deletion cannot reach: the bytes of files that were
deleted *earlier*, still sitting in unallocated clusters.

1. Under **Free-space sweep**, enter a volume or folder — e.g. `D:\` or
   `C:\Users\me\Temp` — or press **Browse...**.
2. Choose the **Pattern**. Random fill is the default and the right choice here.
3. Press **Sweep free space**.

This writes only to unallocated clusters, so it cannot destroy live data —
which is why it is permitted on a system volume where whole-device erasure is
not. What it does **not** do is sanitize slack space inside existing files, or
journal records. The screen says so, and so does the report.

Cancelling a sweep reports how many bytes were overwritten and warns that the
remainder of the free space was not swept. That is a partial result, and the
headline says `CANCELLED` rather than implying the volume is clean.

### Batch results

After a batch, the log reports how many paths were removed out of how many were
attempted. If you cancelled partway, it also reports how many were **never
attempted** — a run told to delete 100 files that stopped after 3 reports
`CANCELLED — 3/3 removed, 97 of 100 path(s) were never attempted`, not
`3/3 removed`. A cancelled batch is recorded in the audit chain as a failure,
because claiming success for work that did not happen is exactly the kind of
false record an audit trail exists to prevent.

---

## 7. Module 3 — Advanced File Carving & Recovery

Recovers files from media where the filesystem no longer helps: formatted
drives, corrupt volumes, wiped or damaged media. It works by content and
structure, not by directory entries.

**Carving is read-only.** The source is opened for reading; only the output
directory is written to. Nothing the recovery module does can damage the
evidence.

### Choosing a source

Press **Open image...** and select the image or device. The line beneath shows
the container type and size, and flags EnCase `E01` images as requiring the
pyewf backend.

Supported: `.img`, `.dd`, `.raw`, `.iso`, `.001`, `.E01`/`.e01`.

### Choosing the scan scope — read this bit

**Whole source** scans every byte. It therefore recovers live files as well as
deleted ones, and **the result set is not on its own evidence of deletion.**

**Unallocated space only** resolves the filesystem's own extent map and scans
only the regions it reports as free. This is what makes a result set mean
"these were deleted", and it is substantially faster.

The second option requires the native backend (pytsk3). If it is not installed,
SANCTUM says so in plain language and falls back to a whole-source scan — and
records in the report that the scope was widened. It does not quietly scan
everything and let you assume otherwise.

### Choosing formats

The **Format filter** lists categories with their format counts. All are
checked by default. **All** and **None** toggle the set; the note below shows
`N of 37 signatures across M categories`.

Narrowing the filter is the single cheapest speed-up: scanning for JPEG and PDF
only is far faster than scanning for all 37 signatures.

### Recovery parameters

| Parameter | Default | Meaning |
|---|---|---|
| **Minimum confidence** | 0 | 0 keeps everything and lets the report rank it. Raise it to cut output to what the scorer is more sure about. |
| **Maximum artefacts** | 5000 | A cap, so a pathological image cannot produce an unbounded result set |
| **Require structural validation** | on | Rejects candidates whose bytes match a header but fail the format's structural parse. This is what suppresses coincidental matches — leave it on. |
| **Write recovered files to disk** | on | Writes each artefact to the output directory with digests recorded |
| **Attempt fragment reassembly (JPEG)** | off | Splices fragments by validating the JPEG marker chain |

> **On fragment reassembly:** structural validity does not prove the extents
> are in their original order. Treat reassembled artefacts as provisional, and
> say so if you rely on one.

### Running it

1. Choose the output directory under **Output**. Nothing is ever written to the
   source.
2. Press **Start recovery**.
3. The results table fills with one row per artefact: **File**, **Category**,
   **Offset**, **Bytes**, **Confidence**, **SHA-256**. Columns are sortable.

### Understanding confidence

Every artefact carries a score out of 100 and a label — **High**, **Medium** or
**Low**. The score is not a black box. Select a row and the detail pane shows
the full derivation:

```
Score derivation
----------------
   +45.0  structural validation: full marker chain parsed
   +25.0  terminator: end-of-image marker found
   +15.0  length plausibility: 148 231 bytes, within the plausible range
   +10.0  entropy: 7.82 bits/byte, consistent with compressed data
   -------
    95.0  total (clamped to 0-100)
```

The weights are named, individually signed, and retained in the output. A
reviewer can recompute the total under a different weighting and see whether
the ranking changes. An opaque score would be unusable as evidence.

**Read the score as a ranking aid, not a fact.** It is heuristic: it tells you
which artefacts are worth opening first, not which are genuine. The SHA-256
digest next to it is a fact.

### Why carving here is not a toy

Most carving tools hunt for a header and then the next footer. That fails on
the first real case, and fails *silently* — it hands back a truncated file that
looks recovered.

The reason is concrete: **a JPEG's EXIF block frequently contains a complete
embedded thumbnail, with its own `FFD9` end-of-image marker.** A naive carver
stops at that marker and returns a corrupt fragment of the outer image.
SANCTUM walks the JPEG marker chain instead, chunk-walks PNG to `IEND`, resolves
ZIP through its end-of-central-directory record, reads PDF to its last `%%EOF`,
and uses declared sizes for BMP and RIFF.

---

## 8. Reports

**Reports** turns the session into a document.

1. Fill in **Case name** and **Examiner**.
2. Under **Operations to include**, tick the operations to cover. **Select
   all** and **Select none** are provided.
3. Under **Output**, choose the formats:
   - **HTML** — self-contained and print-ready. This is the one to hand to a
     reviewer.
   - **JSON** — structured, for re-analysis or ingestion elsewhere.
   - **CSV** — a flat artefact inventory, for spreadsheet work.
4. Set the **Filename stem**.
5. Press **Generate report**, then **Open generated report**.

### What every report states

The report is written to be defensible, which means it states the limitations
that apply to the operations it actually describes — and only those. A report
about an HDD erasure says nothing about wear-levelling; a report about an SSD
erasure says so prominently.

| Report describes | Limitation stated |
|---|---|
| Erasure on flash media | Overwrite is not a proven purge; wear-levelling applies |
| Free-space sweep | Journals and log-structured filesystems retain prior content |
| Carving | Fragmented files may be recovered partially or not at all |
| Any operation | Audit chain integrity state, and confidence scores are heuristic |

### Audit chain integrity in the report

The report renders one of three states, and the distinction matters:

- **intact** — the chain verified from genesis.
- **BROKEN** — with the failing index named, and a statement that the results
  cannot be relied upon.
- **unverified** — no chain was attached to the report.

**`unverified` is never rendered as intact.** That is the single most important
property of this section.

### Markup safety

Filenames come from the media under examination. A report about a suspect's
drive must not execute the suspect's script, so every operator- and
media-supplied string is escaped on the way into the HTML.

---

## 9. The audit chain

**Audit** shows the record of everything this tool has done, and lets you check
it has not been altered.

Each entry is chained to the one before it by a SHA-256 back-link and sealed
with an HMAC. That structure detects:

- **modification** of any field in a sealed entry;
- **forgery** — an entry inserted without the HMAC key;
- **reordering** — the back-links no longer line up;
- **deletion** — a gap appears in the sequence;
- **corruption** — an unparseable line is reported with its index.

Controls: **Verify chain**, **Refresh**, **Export...**. Select a row to inspect
its full payload in the detail pane.

### What the chain is, and is not

It is **tamper-evident**, not tamper-**proof**.

An attacker who can rewrite the entire file can produce a *shorter* chain that
still verifies from its own genesis. A hash chain cannot detect its own
truncation without an external anchor — for example, publishing the chain head
to a separate system. **This is a documented, accepted limitation, not an
oversight**, and it is stated in the report rather than buried.

Every refusal is recorded too, with outcome `DENIED` and the specific reason.
An attempt that was blocked is as much a part of the record as one that
succeeded.

---

## 10. Settings and the safety interlocks

This is where the safety model becomes visible.

### Three independent keys for raw devices

Writing to a real physical device requires **all three** of these:

| # | Key | Where it lives | Default |
|---|---|---|---|
| 1 | `Allow writing to physical (raw) devices` | This screen | off |
| 2 | `SANCTUM_ALLOW_RAW_DEVICE` environment variable | Outside the application | unset |
| 3 | A typed confirmation token | At the point of use | required |

The **Raw-device interlocks** card shows the live state of all three, including
the ones the screen cannot change:

```
1. Policy flag (this screen)          : not set
2. SANCTUM_ALLOW_RAW_DEVICE environment : not set
3. Confirmation token (at point of use): required

Raw devices are locked. Missing: the policy flag above and the
SANCTUM_ALLOW_RAW_DEVICE environment variable.
```

That design is deliberate. **A misclick should not be sufficient to destroy a
disk, and an environment variable cannot be set by a misclick.**

To satisfy the second key, set it *before* launching:

```bash
# Windows PowerShell
$env:SANCTUM_ALLOW_RAW_DEVICE = "1"
python run.py

# Linux / macOS
SANCTUM_ALLOW_RAW_DEVICE=1 python run.py
```

Press **Re-check environment** after setting it in another terminal.

### Two unconditional refusals

These cannot be overridden by any setting:

- **The running operating system's own drive.** Always refused.
- **SANCTUM's own data directory.** Always refused, for device and file
  targets alike.

### The other policy switches

- **Dry run — never write to a target.** On by default. With it on, every
  module plans the operation in full, writes audit records, and reports what it
  *would* have done, without touching the target.
- **Require a typed confirmation token.** On by default.

### Runtime paths

The **Runtime paths** card shows the data directory, cases directory, and logs
directory, and whether `SANCTUM_HOME` is set. Set `SANCTUM_HOME` before
launching to relocate all three — useful for keeping an engagement's data on a
separate volume.

### Effective policy

The read-only box at the bottom shows the exact policy string. **That string is
written into the audit chain at the start of every destructive operation**, so
a reviewer can reconstruct which policy was in force when the work was done.

---

## 11. Command line

| Command | What it does |
|---|---|
| `python run.py` | Launch the desktop application |
| `python run.py --selftest` | Build media, run all three modules, report PASS/FAIL |
| `python run.py --make-media DIR` | Build synthetic evidence images into `DIR` |
| `python run.py --version` | Print the version |
| `python run.py --workdir DIR` | Working directory for `--selftest` |
| `python run.py --keep` | Keep the temporary files `--selftest` creates |
| `python -m pytest tests -q` | Run the test suite |
| `python -m tools.benchmark --quick` | Indicative performance figures |
| `python -m tools.benchmark` | Full performance measurement |

`--selftest` exits non-zero if anything fails, so it can be used in a script or
as a smoke test on a new machine.

### Building demo media

```bash
python run.py --make-media testdata
```

This writes:

- a 16 MiB FAT16 image with ten deleted files and two live ones, plus a
  `manifest.json` recording each file's size, cluster chain and SHA-256 digest;
- a fragmented-files image;
- a pre-wiped image;
- a blank scratch image.

That manifest is what lets `--selftest` make a falsifiable claim about
recovery — it compares recovered bytes against recorded digests rather than
counting artefacts and hoping.

---

## 12. Troubleshooting

**"Start erasure" is disabled and the tooltip says I need the environment
unlock.**
You ticked the raw-device checkbox but `SANCTUM_ALLOW_RAW_DEVICE` is not set.
See §10. This is the second key working as intended.

**"Confirmation token mismatch."**
The token is derived from the target's path, *size* and *serial*. If the file
at that path changed since the token was displayed — including being written to
by a dry run, in some cases — the token changes. Re-select the target and use
the token now shown.

**Recovery found nothing, or far less than expected.**
Check, in order: (1) the format filter — a narrowed filter is the usual cause;
(2) the scan scope — *unallocated only* requires pytsk3, and without it the
scan widens to the whole source; (3) **Minimum confidence** — if it is above 0,
low-confidence artefacts are being dropped; (4) whether the data was
overwritten rather than merely unlinked.

**An SSD reports "verified" but I do not believe it.**
Read the media warning. On flash, a verified overwrite means the blocks
SANCTUM wrote contain the expected pattern — it does **not** mean the original
data is gone. Use the drive's own SANITIZE command for that.

**The report says `unverified` for the audit chain.**
No chain was attached to the report. Generate the report from the **Reports**
page with a case open, so the chain is included.

**A case will not open.**
A corrupt case directory is skipped rather than blocking the list, so other
cases remain available. Inspect the case directory under the path shown in
**Settings → Runtime paths**.

**PyQt6 is not installed.**
The engines, the command line, `--selftest` and the test suite all work
without it. Only the interface needs it.

---

## 13. Glossary

**Artefact** — a file recovered by carving, with its offset, length, digests
and confidence score.

**Carving** — recovering files by their content and structure, without using
filesystem metadata.

**Chain of custody** — the record of who held evidence, when, and in what
state. SANCTUM's evidence register and audit chain together provide this.

**Confidence score** — a 0–100 ranking aid computed from named, weighted,
individually-visible factors.

**Dry run** — a full plan and audit record with no writes to the target. The
default.

**Free-space sweep** — overwriting unallocated clusters to remove the residue
of previously deleted files.

**HMAC** — a keyed message authentication code. SANCTUM uses HMAC-SHA-256 to
seal each audit entry so that an entry cannot be forged without the key.

**Interlock** — one of the independent conditions that must hold before a
dangerous operation proceeds. See §10.

**Media type** — HDD, SSD, NVMe, USB flash, SD card, optical, or unknown.
Determines whether an overwrite is a genuine purge, and therefore whether the
tool warns.

**Purge** — in NIST terminology, rendering data recovery infeasible even with
laboratory techniques. Distinct from **clear**, which defeats ordinary
recovery. An overwrite on magnetic media is a clear; on flash it may be
neither, which is why the tool warns.

**Standard** — a named, published overwrite scheme with a defined pass
structure. SANCTUM implements nine.

**Structural validation** — parsing a candidate's bytes according to its
format's own rules (JPEG marker chain, PNG chunk walk, ZIP central directory)
rather than looking for a footer. This is what separates a real recovery from a
plausible fragment.

**Tamper-evident** — alteration is detectable. Not the same as tamper-proof,
which would mean alteration is impossible. See §9.

**Unallocated space** — regions a filesystem reports as free. Scanning only
these is what makes a recovery result meaningful as evidence of deletion.

**Verification** — reading the target back and comparing it against what was
supposed to be written. Sampled or full. `unverified` is a distinct state from
`failed`.
