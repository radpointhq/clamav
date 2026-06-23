# DICOM handler for ClamAV — design & development notes

A native `CL_TYPE_DICOM` container handler added to a fork of ClamAV (`radpointhq/clamav`,
branch `dicom-handler`, off upstream tag `clamav-1.4.4`). It teaches the engine to understand
the DICOM medical-imaging format so that malware hidden inside DICOM structure is extracted and
scanned — closing the "DICOM blind spot" where compressed/encapsulated payloads evade raw
signature matching. It replaces the standalone `dicom-antivirus` ("venkman") HTTP service.

> Status: handler functionally complete, fuzzed, and CI-guarded. Deployed as a clamd **sidecar**
> reached over INSTREAM from `purgatory` (the C++ upload orchestrator). See
> `PURGATORY_HANDOFF.md` in the `dicom-antivirus` repo for the consumer side.

---

## 1. Why this exists

ClamAV natively unpacks ZIP, PDF, OLE2, etc., but has **no DICOM parser**. A DICOM file can hide
executable or malicious content in places a flat signature scan cannot see:

- **compressed/encapsulated pixel data** (JPEG / JPEG 2000 / RLE fragments),
- **deflated datasets** (Deflated Explicit VR Little Endian),
- **embedded documents** (an encapsulated PDF/CDA),
- and the **128-byte preamble**, which the standard leaves unspecified — the basis of the
  CVE-2019-11687 polyglot (a file that is simultaneously a valid DICOM image and a valid `.exe`).

The handler walks the DICOM structure, decodes those layers, and re-injects each extracted object
back into the engine, so ClamAV's existing recursion and signatures apply to the *real* content.

## 2. Architecture

The handler mirrors how every other ClamAV container type is wired (`unzip.c` was the template):

```
file typed CL_TYPE_DICOM  ──▶  cli_scandicom(ctx)            (libclamav/dicom.c)
                                 ├─ inspect 128-byte preamble (polyglot heuristic)
                                 ├─ parse File Meta group → TransferSyntaxUID
                                 ├─ walk data-element stream
                                 │    ├─ encapsulated pixel data → each fragment
                                 │    ├─ native pixel data (OB/OW)
                                 │    ├─ encapsulated documents (0042,0011)
                                 │    └─ sequences (SQ), nested
                                 └─ deflated dataset → inflate
                                        │
                                        ▼
              cli_magic_scan_nested_fmap_type() / cli_magic_scan_buff()
                 → engine re-detects type & recurses (ZIP/PNG/PE/PDF inside
                   a fragment all get their native parsers), under the usual
                   MaxRecursion / MaxFiles / MaxScanSize limits.
```

**Integration points (the minimal, rebase-friendly footprint):**

| Change | File |
|---|---|
| `CL_TYPE_DICOM` enum value | `libclamav/filetypes.h` |
| name→code map entry | `libclamav/filetypes.c` (`ftmap[]`) |
| built-in magic: `DICM` at offset 128 | `libclamav/filetypes_int.h` |
| dispatch `case CL_TYPE_DICOM` | `libclamav/scanners.c` |
| the handler | `libclamav/dicom.c` + `dicom.h` |
| build entry | `libclamav/CMakeLists.txt` |

Everything else is additive (fuzz target, tests, Docker, CI). The handler is the only engine code
touched, so rebasing onto new ClamAV releases stays cheap.

## 3. What the handler covers

| Capability | Transfer syntax / element | How |
|---|---|---|
| File Meta + transfer-syntax classification | group `0002`, `(0002,0010)` | always Explicit VR LE |
| Implicit / Explicit VR, Little Endian | `1.2.840.10008.1.2`, `…1.2.1` | element walk |
| **Explicit VR Big Endian** (retired) | `1.2.840.10008.1.2.2` | endian-aware reads (`dicom_rd16/rd32`) |
| **Deflated** dataset | `1.2.840.10008.1.2.1.99` | raw inflate (zlib `-MAX_WBITS`) → scan |
| **Encapsulated** pixel data | JPEG family `…1.2.4.*`, RLE `…1.2.5` | per-fragment item walk → scan each |
| Native pixel data | `(7FE0,0010)` defined length | OB/OW re-injected |
| Embedded documents | `(0042,0011)` | re-injected (PDF/CDA get native parsing) |
| Sequences | `SQ`, defined & undefined length, nested | recurse (depth-capped at 16) |
| Implicit-VR defined-length SQ | (no VR field) | inferred by content-peek (item tag `FFFE,E000`) |
| **Preamble polyglots** | 128-byte preamble | heuristic: PE / ELF / Mach-O / `#!` |

### Safety properties (hostile input is the norm here)

- Every read goes through `fmap_need_off_once()` (bounds-checked).
- Every extracted child is gated by `cli_checklimits()` (skip, never fail the whole scan).
- `cli_checktimelimit()` is honored in every loop; each loop iteration advances ≥ 8 bytes.
- SQ recursion is capped (and the engine's `MaxRecursion` also applies).
- Deflate output is capped at `maxscansize` (zip-bomb guard).
- A malformed element stream **degrades to a clean verdict with a debug log**, not a scan error —
  the engine's raw scan still covers bytes the walk couldn't interpret.
- A worker fault would crash the whole clamd daemon, so the parser is **fuzzed** (see §6).

## 4. CVE coverage assessment

DICOM-related CVEs fall into three classes; only the first is an AV scanner's responsibility.

**Class 1 — malware hiding in a DICOM file (our job): covered.**

| Vector | Reference | Coverage |
|---|---|---|
| PE/DICOM preamble polyglot | **CVE-2019-11687** | `main.cvd` `Win.Exploit.CVE_2019_11687` **+** `Heuristics.DICOM.ExecutableInPreamble.PE` |
| ELF preamble polyglot | **ELFDICOM** (Praetorian) | `Heuristics.DICOM.ExecutableInPreamble.ELF` (+ Mach-O, `#!`) |
| compressed pixel-data payloads | DHS/Cylera advisory | per-fragment extraction → scan |
| embedded documents | DHS/Cylera advisory | `(0042,0011)` extraction |
| deflated-dataset payloads | — | inflate → scan |

The preamble heuristic runs in the **generic scan path** (`cli_dicom_check_preamble_polyglot`,
called from `cli_magic_scan`), *not* inside the DICOM handler. This is deliberate and important: a
real polyglot has its executable magic at offset 0, so ClamAV types it as `CL_TYPE_MSEXE`/`ELF` and
would never dispatch to `cli_scandicom`. The check therefore runs for every file, gated on `DICM`
being present at offset 128 (so ordinary executables are unaffected), and catches *unknown* payloads
(e.g. ELF/zero-day) the signature DB does not.

It surfaces via `cli_append_potentially_unwanted()`, so the sidecar must run with
**`HeuristicScanPrecedence yes`** (set in `docker/clamd.conf`) for the match to be a reported, hard
alert rather than a silent potentially-unwanted indicator — the correct fail-closed posture for a
gate. (Heuristics themselves are on by clamd default; precedence is what makes the verdict surface.)

**Class 2 — memory-safety bugs in DICOM *parsers*** (GDCM CVE-2024-22391/22373/25569,
CVE-2025-48429/52582/11266; DCMTK `DcmRLEDecoder`, `determineMinMax`): these are bugs in *other*
software, not malware an AV detects. They are instead a **self-audit checklist for our parser** —
addressed by bounds-checking + fuzzing, and exercised by the crash-safety corpus (§5).

**Class 3 — network / server CVEs** (DCMTK `dcmnet`, Orthanc auth-bypass CVE-2025-0896): the
DIMSE/ACSE protocol and server config — **out of scope** for a file content scanner.

## 5. Tests

`unit_tests/dicom_handler/`:

- **`generate_corpus.py`** — builds a dummy signature DB (`test.ndb`) plus a corpus. No real
  malware: each *infected* file hides a fixed 20-byte marker, and the generator **asserts the
  marker is absent from the raw bytes**, so a detection genuinely proves structural extraction.
  - *infected* (must detect): `encap_zip`, `sq_doc`, `native_pixel`, `deflated_evil`,
    `implicit_sq`, `bigendian_pixel`, `pe_polyglot`, `elf_polyglot`.
  - *clean* (must pass): well-formed variants, plus malformed/adversarial controls modeled on the
    GDCM/DCMTK CVE shapes — `mal_frag_underflow`, `mal_rle_huge`, `mal_huge_elem`, `mal_deep_sq`,
    `mal_zero_items`, `mal_truncated`, `mal_nodelim`, `bad_meta`, `frag_bad`, `zero_preamble`.
- **`run_tests.sh <clamscan>`** — scans the corpus, asserts infected→detected, clean→OK.
- **`generate_seeds.py`** — writes the corpus as a libFuzzer seed corpus.

> Note on test signatures: ClamAV's `Eicar-Test-Signature` is **anchored/whole-file**, so EICAR
> can't probe *embedded* detection (EICAR at a non-zero offset is not matched). Use the
> non-anchored `.ndb` marker (as the corpus does) for embedded-detection tests.

## 6. Fuzzing

DICOM is registered in `fuzz/CMakeLists.txt` `SCAN_TARGETS`, generating
`clamav_scanmap_DICOM_fuzzer` / `clamav_scanfile_DICOM_fuzzer` from the existing harnesses.
`CLAMAV_FUZZ_DICOM` enables `CL_SCAN_PARSE_ARCHIVE` (what gates the DICOM dispatch).

CI runs a bounded 120 s ASan fuzz over the seed corpus on every push/PR. Latest runs:
**~385k–422k executions, zero crashes.** The crash-safety corpus files seed it, so the
CVE-shaped malformed inputs get continuous ASan coverage.

## 7. Deployment — clamd sidecar (Model A)

A multi-stage `Dockerfile` builds the forked libclamav, **bakes a pinned freshclam signature
snapshot**, and ships a minimal clamd that purgatory reaches over INSTREAM on **TCP 3310**.

- Build and runtime share `debian:bookworm` / `bookworm-slim` so the self-built `libclamav.so`
  links against matching libraries (avoiding the ABI mismatch the old venkman alpine image had).
- `docker/clamd.conf`: TCP 3310, `TemporaryDirectory /tmp` (**mount a tmpfs there at deploy for
  PHI safety**), size limits (study-size + zip-bomb guards), `MaxThreads` (concurrent scans),
  `AlertExceedsMax yes` (fail **closed** on oversized input rather than silently passing it),
  `HeuristicScanPrecedence yes` (surfaces the preamble-polyglot heuristic as a hard alert),
  foreground logging to stderr. clamd logs `DICOM (medical imaging) support enabled` at startup
  (gated on `ScanArchive`).
- **2 GiB single-object cap (hard ClamAV limit).** `MaxFileSize`/`StreamMaxLength` above
  `INT_MAX-2` (≈2 GiB) are silently clamped (`libclamav/others.c`), and a file over the cap is
  skipped, so a large study **zip cannot be scanned as one object**. The orchestrator must unzip and
  stream each DICOM instance (< 2 GiB) individually — per-member fan-out (`PURGATORY_HANDOFF.md`).
  `MaxScanSize` is 64-bit (the aggregate-per-object budget) and is set with headroom (10 GiB).
- `docker/freshclam.conf`: build-time only; the runtime image does **not** auto-update — updating
  signatures means rebuilding the image (pinned, deliberate updates).

Validated end-to-end: image builds (~774 MB), clamd answers PING in ~8 s, and INSTREAM scans
detect EICAR, a PE/DICOM polyglot, and pass a clean DICOM; the daemon survives the malformed
corpus (0 restarts).

### Gotchas learned (baked into the files)

- The build stage needs **`build-essential`** (gcc/g++/make) — `cmake` alone isn't enough.
- freshclam at build must set **`DatabaseOwner root`** (no `clamav` user exists in the build stage)
  and must **not** log to `/dev/stdout` (symlink-chain error).
- clamd in foreground logs to **stderr**; do not set `LogFile /dev/stdout`.
- `docker cp` into a **tmpfs**-mounted path is not visible to the process — stream via stdin
  (`clamdscan - < file`) instead.

## 8. CI

`.github/workflows/` (upstream's `cmake.yml` does not trigger on this branch, so these are added):

- **`dicom-handler.yml`** — `build-and-test` (build clamscan, run the corpus) + `fuzz` (build the
  DICOM fuzzer with clang+libFuzzer+ASan, 120 s bounded run). Triggers on push to `dicom-handler`
  and PRs touching the handler.
- **`clamd-image.yml`** — builds the sidecar image on every push/PR (validates the Dockerfile, no
  AWS needed) and **pushes to ECR** with `${sha}` + `ci-bb` tags once the repo variables
  `AWS_ROLE_ARN`, `AWS_REGION`, `ECR_REPOSITORY` are set (until then the push steps skip, CI stays
  green).

## 9. Build & run locally

```bash
# Build the engine + clamscan (macOS deps: brew install rust pkg-config libxml2 json-c check)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_TESTS=OFF -DENABLE_MILTER=OFF -DENABLE_MAN_PAGES=OFF \
  -DENABLE_CLAMONACC=OFF -DENABLE_SYSTEMD=OFF \
  -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
cmake --build build --target clamscan -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

# Run the DICOM handler tests
./unit_tests/dicom_handler/run_tests.sh ./build/clamscan/clamscan

# Build & run the sidecar
docker build -t clamav-dicom .
docker run -d --name clamd --tmpfs /tmp -p 3310:3310 clamav-dicom
clamdscan -                     # stream over INSTREAM (or: clamdscan - < some.dcm)
```

## 10. Known gaps / future work

- Implicit-VR SQ detection is a content heuristic, not a full tag dictionary (acceptable — a false
  positive just bails to `CL_EPARSE`; the value is still raw-scanned).
- A longer **scheduled** fuzz campaign (nightly cron) beyond the 120 s PR smoke run.
- Set the ECR repo variables to activate image push to the swarm `ci-bb` flow.
- Consider **upstreaming** `CL_TYPE_DICOM` to Cisco Talos to retire the fork-maintenance burden.

## 11. References

- CVE-2019-11687 — DICOM Part 10 preamble PE polyglot.
- ELFDICOM — Praetorian, 2025 (ELF extension of the above).
- "Malware in DICOM" — DHS / Cylera advisory (encapsulated docs & compressed pixel data).
- GDCM/DCMTK parser CVEs — Cisco Talos vulnerability reports (parser memory-safety classes).
