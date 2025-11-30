#!/usr/bin/env python3
import sys
import json
import pikepdf
from pathlib import Path

def extract_sampled_functions(pdf_path, out_prefix):
    pdf = pikepdf.open(pdf_path)

    results = []
    func_index = 0

    # Iterate over all objects in the PDF
    for obj in pdf.objects:
        # We only care about stream objects (functions with streams)
        if not isinstance(obj, pikepdf.Stream):
            continue

        d = obj.get("/FunctionType", None)
        if d is None:
            continue

        try:
            ftype = int(d)
        except Exception:
            continue

        # Only pick FunctionType 0 (Sampled functions)
        if ftype != 0:
            continue

        func_dict = obj

        # Extract dictionary fields
        bits_per_sample = int(func_dict.get("/BitsPerSample", 0))

        size_obj = func_dict.get("/Size", None)
        if size_obj is not None:
            size_vals = [int(x) for x in size_obj]
        else:
            size_vals = []

        domain_obj = func_dict.get("/Domain", None)
        if domain_obj is not None:
            domain_vals = [float(x) for x in domain_obj]
        else:
            domain_vals = []

        range_obj = func_dict.get("/Range", None)
        if range_obj is not None:
            range_vals = [float(x) for x in range_obj]
        else:
            range_vals = []

        length = int(func_dict.get("/Length", 0))

        # Read stream bytes
        stream_bytes = bytes(obj.read_bytes())
        actual_len = len(stream_bytes)

        # Save stream to a separate binary file
        bin_name = f"{out_prefix}_func{func_index}.bin"
        with open(bin_name, "wb") as fbin:
            fbin.write(stream_bytes)

        info = {
            "index": func_index,
            "BitsPerSample": bits_per_sample,
            "Size": size_vals,
            "Domain": domain_vals,
            "Range": range_vals,
            "DeclaredLength": length,
            "ActualLength": actual_len,
            "StreamFile": bin_name,
        }
        results.append(info)
        func_index += 1

    # Write JSON metadata
    json_name = f"{out_prefix}_functions.json"
    with open(json_name, "w", encoding="utf-8") as fout:
        json.dump(results, fout, indent=2)

    print(f"Extracted {len(results)} FunctionType 0 functions")
    print(f"- Metadata written to: {json_name}")
    for r in results:
        print(f"- Stream #{r['index']} → {r['StreamFile']} (len={r['ActualLength']})")


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 extract_sampled_func.py input.pdf out_prefix")
        sys.exit(1)

    pdf_path = sys.argv[1]
    out_prefix = sys.argv[2]
    extract_sampled_functions(pdf_path, out_prefix)


if __name__ == "__main__":
    main()
