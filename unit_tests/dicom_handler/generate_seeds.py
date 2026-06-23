#!/usr/bin/env python3
"""
Write a libFuzzer seed corpus for the DICOM handler into the given directory.

These are small, valid (and a few deliberately edge-case) DICOM files that
exercise every branch of the handler: implicit/explicit VR, deflated and
encapsulated transfer syntaxes, nested sequences, encapsulated documents, and
malformed length fields. The fuzzer mutates from these to reach the parser
deeply instead of wasting cycles trying to randomly produce "DICM" at
offset 128.
"""

import os
import sys

# reuse the corpus builder; its infected+clean files are ideal fuzz seeds
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate_corpus  # noqa: E402


def main(outdir):
    tmp = os.path.join(outdir, ".build")
    generate_corpus.build(tmp)
    os.makedirs(outdir, exist_ok=True)
    count = 0
    for sub in ("infected", "clean"):
        d = os.path.join(tmp, sub)
        for name in os.listdir(d):
            if not name.endswith(".dcm"):
                continue
            with open(os.path.join(d, name), "rb") as f:
                data = f.read()
            with open(os.path.join(outdir, "seed_%s_%s" % (sub, name)), "wb") as f:
                f.write(data)
            count += 1
    print("wrote %d DICOM seeds to %s" % (count, outdir))


if __name__ == "__main__":
    ap_out = sys.argv[1] if len(sys.argv) > 1 else "dicom_seeds"
    main(ap_out)
