#!/usr/bin/env python3
"""
Generate the DICOM-handler test corpus and a dummy signature database.

Produces, in the output directory:
  - test.ndb            a single dummy signature (TestSig) matching a fixed
                        20-byte marker, so no real malware is needed in CI.
  - infected/*.dcm      DICOM files that hide the marker from a raw byte scan
                        in different structural ways; each MUST be detected
                        only via the DICOM handler's structural walk.
  - clean/*.dcm         well-formed and deliberately-malformed DICOM files
                        that MUST NOT be flagged.

The marker is never present verbatim in an infected file (the generator
asserts this), so detection proves the handler extracted and re-scanned the
embedded object rather than the engine matching it in the raw bytes.
"""

import argparse
import os
import struct
import zlib

# Fixed marker; the dummy .ndb signature matches exactly these bytes.
MARKER = bytes.fromhex("deadbeefcafebabe1337")


def elem_short(group, elem, vr, value):
    """Explicit-VR element with a 16-bit length (UI, PN, UL, ...)."""
    if len(value) % 2:
        value += b"\x00"
    return struct.pack("<HH", group, elem) + vr + struct.pack("<H", len(value)) + value


def elem_long(group, elem, vr, value, undefined=False):
    """Explicit-VR element with a 2-byte reserved field + 32-bit length."""
    if len(value) % 2:
        value += b"\x00"
    length = 0xFFFFFFFF if undefined else len(value)
    return (
        struct.pack("<HH", group, elem)
        + vr
        + b"\x00\x00"
        + struct.pack("<I", length)
        + value
    )


def item(payload):
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(payload)) + payload


ITEM_DELIM = struct.pack("<HHI", 0xFFFE, 0xE00D, 0)
SEQ_DELIM = struct.pack("<HHI", 0xFFFE, 0xE0DD, 0)


def dicom(transfer_syntax, dataset):
    """Wrap a dataset in a 128-byte preamble, 'DICM', and a File Meta group."""
    meta = elem_short(0x0002, 0x0010, b"UI", transfer_syntax.encode())
    grouplen = elem_short(0x0002, 0x0000, b"UL", struct.pack("<I", len(meta)))
    return b"\x00" * 128 + b"DICM" + grouplen + meta + dataset


def evil_zip():
    """A ZIP whose DEFLATE-compressed member hides the marker."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("payload.bin", MARKER + b"A" * 200)
    data = buf.getvalue()
    assert MARKER not in data, "marker must be hidden by deflate"
    return data


def build(outdir):
    infected = os.path.join(outdir, "infected")
    clean = os.path.join(outdir, "clean")
    os.makedirs(infected, exist_ok=True)
    os.makedirs(clean, exist_ok=True)

    with open(os.path.join(outdir, "test.ndb"), "w") as f:
        f.write("TestSig:0:*:%s\n" % MARKER.hex())

    pn = elem_short(0x0010, 0x0010, b"PN", b"TEST^PATIENT")
    ez = evil_zip()

    TS_EXPLICIT = "1.2.840.10008.1.2.1"
    TS_IMPLICIT = "1.2.840.10008.1.2"
    TS_DEFLATED = "1.2.840.10008.1.2.1.99"
    TS_JPEG2K = "1.2.840.10008.1.2.4.90"

    written = {}

    infected_names = (
        "encap_zip",
        "sq_doc",
        "native_pixel",
        "deflated_evil",
        "implicit_sq",
        "bigendian_pixel",
        "pe_polyglot",
        "elf_polyglot",
    )

    def emit(subdir, name, data):
        if name in infected_names:
            assert MARKER not in data, "%s leaks the marker in raw bytes" % name
        path = os.path.join(subdir, name + ".dcm")
        with open(path, "wb") as f:
            f.write(data)
        written[name] = len(data)

    # --- infected: marker reachable only through the structural walk --------

    # encapsulated pixel data: basic offset table (empty) + fragment = evil zip
    encap = (
        struct.pack("<HH", 0x7FE0, 0x0010)
        + b"OB\x00\x00"
        + struct.pack("<I", 0xFFFFFFFF)
        + item(b"")
        + item(ez)
        + SEQ_DELIM
    )
    emit(infected, "encap_zip", dicom("1.2.840.10008.1.2.4.70", pn + encap))

    # undefined-length SQ -> undefined-length item -> EncapsulatedDocument
    doc = elem_long(0x0042, 0x0011, b"OB", ez)
    sq = (
        struct.pack("<HH", 0x0008, 0x1140)
        + b"SQ\x00\x00"
        + struct.pack("<I", 0xFFFFFFFF)
        + struct.pack("<HHI", 0xFFFE, 0xE000, 0xFFFFFFFF)
        + doc
        + ITEM_DELIM
        + SEQ_DELIM
    )
    emit(infected, "sq_doc", dicom(TS_EXPLICIT, pn + sq + pn))

    # native (defined-length) pixel data = evil zip
    native = elem_long(0x7FE0, 0x0010, b"OW", ez)
    emit(infected, "native_pixel", dicom(TS_EXPLICIT, pn + native))

    # implicit VR, defined-length SQ (no VR field): item holds the evil zip in
    # an implicit-VR element. The handler must infer SQ from the item tag and
    # recurse to reach the hidden marker.
    def elem_implicit(group, elem, value):
        if len(value) % 2:
            value += b"\x00"
        return struct.pack("<HHI", group, elem, len(value)) + value

    inner = elem_implicit(0x0042, 0x0011, ez)  # EncapsulatedDocument, implicit
    sq_body = item(inner)
    isq = elem_implicit(0x0008, 0x1199, sq_body)  # defined-length SQ-ish tag
    emit(infected, "implicit_sq", dicom(TS_IMPLICIT, elem_implicit(0x0010, 0x0010, b"TEST^PATIENT") + isq))

    # retired Explicit VR Big Endian: tags and lengths are byte-swapped; the
    # native pixel data holds the evil zip. The handler must read big-endian
    # tag/length fields to reach it.
    def elem_long_be(group, elem, vr, value):
        if len(value) % 2:
            value += b"\x00"
        return (
            struct.pack(">HH", group, elem)
            + vr
            + b"\x00\x00"
            + struct.pack(">I", len(value))
            + value
        )

    def dicom_be(dataset):
        # File Meta is ALWAYS Explicit VR LE, even for a big-endian dataset
        meta = elem_short(0x0002, 0x0010, b"UI", b"1.2.840.10008.1.2.2")
        grouplen = elem_short(0x0002, 0x0000, b"UL", struct.pack("<I", len(meta)))
        return b"\x00" * 128 + b"DICM" + grouplen + meta + dataset

    be_pn = struct.pack(">HH", 0x0010, 0x0010) + b"PN" + struct.pack(">H", 12) + b"TEST^PATIENT"
    be_pixel = elem_long_be(0x7FE0, 0x0010, b"OW", ez)
    emit(infected, "bigendian_pixel", dicom_be(be_pn + be_pixel))

    # deflated dataset (raw DEFLATE) hiding the marker in an OB element
    raw = pn + (
        struct.pack("<HH", 0x0009, 0x0010)
        + b"OB\x00\x00"
        + struct.pack("<I", len(MARKER) + 200)
        + MARKER
        + b"B" * 200
    )
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = co.compress(raw) + co.flush()
    emit(infected, "deflated_evil", dicom(TS_DEFLATED, deflated))

    # preamble polyglots (CVE-2019-11687 / ELFDICOM): an executable header in
    # the unspecified 128-byte preamble. No signature payload — detection is
    # purely the structural heuristic. (Requires heuristics enabled, the
    # default for clamscan/clamd.)
    emit(infected, "pe_polyglot", b"MZ" + b"\x90" * 126 + b"DICM" + dicom(TS_EXPLICIT, pn))
    emit(infected, "elf_polyglot", b"\x7fELF" + b"\x00" * 124 + b"DICM" + dicom(TS_EXPLICIT, pn))

    # --- clean: must scan OK (well-formed and malformed) --------------------

    # conformant all-zero preamble: must NOT trip the polyglot heuristic
    emit(clean, "zero_preamble", b"\x00" * 128 + b"DICM" + dicom(TS_EXPLICIT, pn))
    emit(clean, "clean", dicom(TS_EXPLICIT, pn))
    emit(clean, "implicit", dicom(TS_IMPLICIT, pn))
    emit(clean, "deflated_clean", dicom(TS_DEFLATED, (lambda d: (lambda c: c.compress(d) + c.flush())(zlib.compressobj(9, zlib.DEFLATED, -15)))(pn)))
    emit(clean, "jpeg2k", dicom(TS_JPEG2K, pn))
    emit(clean, "unknown_ts", dicom("1.2.3.4.5.6.7.8.9", pn))

    # malformed: meta element length far exceeding file size
    bad_meta = (
        b"\x00" * 128
        + b"DICM"
        + struct.pack("<HH", 0x0002, 0x0010)
        + b"UI"
        + struct.pack("<H", 0xFFFF)
    )
    emit(clean, "bad_meta", bad_meta)

    # malformed: encapsulated fragment claiming a length beyond the file
    frag_bad = dicom(
        "1.2.840.10008.1.2.4.70",
        pn
        + struct.pack("<HH", 0x7FE0, 0x0010)
        + b"OB\x00\x00"
        + struct.pack("<I", 0xFFFFFFFF)
        + struct.pack("<HHI", 0xFFFE, 0xE000, 0x7FFFFFFF),
    )
    emit(clean, "frag_bad", frag_bad)

    # Adversarial / malformed inputs modeled on the GDCM/DCMTK parser-bug CVE
    # classes (OOB read/write, integer underflow, recursion). The handler must
    # bail cleanly without crashing; these double as ASan fuzz seeds.
    TS_RLE = "1.2.840.10008.1.2.5"

    def encap(ts, *items_bytes):
        body = struct.pack("<HH", 0x7FE0, 0x0010) + b"OB\x00\x00" + struct.pack("<I", 0xFFFFFFFF)
        for ib in items_bytes:
            body += ib
        return dicom(ts, pn + body)

    def raw_item(length, payload=b""):
        return struct.pack("<HHI", 0xFFFE, 0xE000, length) + payload

    # CVE-2025-11266 class: encapsulated fragment length near 2^32 (underflow)
    emit(clean, "mal_frag_underflow", encap(TS_JPEG2K, raw_item(0xFFFFFFFE)))
    # CVE-2025-48429 class: RLE fragment claiming an enormous segment table
    emit(clean, "mal_rle_huge", encap(TS_RLE, raw_item(0x7FFFFFFF, b"\x10\x00\x00\x00")))
    # huge defined-length element in a tiny file (OOB read guard)
    emit(clean, "mal_huge_elem",
         dicom(TS_EXPLICIT, pn + struct.pack("<HH", 0x0009, 0x0010) + b"OB\x00\x00"
               + struct.pack("<I", 0x7FFFFFFF) + b"AB"))
    # recursion bomb: 40 nested undefined-length SQs (beyond the depth cap)
    sq = b""
    for _ in range(40):
        sq = (struct.pack("<HH", 0x0008, 0x1140) + b"SQ\x00\x00" + struct.pack("<I", 0xFFFFFFFF)
              + struct.pack("<HHI", 0xFFFE, 0xE000, 0xFFFFFFFF) + sq)
    emit(clean, "mal_deep_sq", dicom(TS_EXPLICIT, pn + sq))
    # 50 zero-length pixel-data items (loop must advance >= 8 bytes each)
    emit(clean, "mal_zero_items",
         encap(TS_JPEG2K, *([raw_item(0)] * 50), struct.pack("<HHI", 0xFFFE, 0xE0DD, 0)))
    # truncated mid-element
    emit(clean, "mal_truncated",
         dicom(TS_EXPLICIT, pn + struct.pack("<HH", 0x0009, 0x0010) + b"OB\x00\x00"
               + struct.pack("<I", 9999) + b"AB"))
    # undefined-length pixel data, no sequence delimiter (runs to EOF)
    emit(clean, "mal_nodelim", encap(TS_JPEG2K, raw_item(4, b"ABCD")))

    for name in sorted(written):
        print("  %-16s %d bytes" % (name, written[name]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", help="directory to write the corpus into")
    args = ap.parse_args()
    build(args.outdir)
    print("DICOM corpus written to %s" % args.outdir)
