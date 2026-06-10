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

    def emit(subdir, name, data):
        if name in ("encap_zip", "sq_doc", "native_pixel", "deflated_evil"):
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

    # --- clean: must scan OK (well-formed and malformed) --------------------

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

    for name in sorted(written):
        print("  %-16s %d bytes" % (name, written[name]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", help="directory to write the corpus into")
    args = ap.parse_args()
    build(args.outdir)
    print("DICOM corpus written to %s" % args.outdir)
