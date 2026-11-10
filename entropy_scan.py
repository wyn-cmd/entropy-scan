# entropy_scan: find high-entropy regions inside a file
# A sliding window computes Shannon entropy over the byte stream and
# windows sitting above the threshold get merged into reportable regions,
# so packed, encrypted or compressed payloads stand out from plain data.

import argparse
import json
import math
import sys
from collections import Counter

# Signatures checked at the start of a region so a hit can be named
MAGIC_SIGNATURES = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"BZh", "bzip2"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"Salted__", "openssl-salted"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF-", "pdf"),
]


# Shannon entropy of a byte string in bits per byte, ranging from 0.0 to 8.0
def shannon_entropy(chunk):
    if not chunk:
        return 0.0
    counts = Counter(chunk)
    total = len(chunk)
    score = 0.0
    for count in counts.values():
        probability = count / total
        score -= probability * math.log2(probability)
    return score


# Yield (offset, window) pairs that cover the whole buffer, tail included
def iter_windows(data, window, step):
    length = len(data)
    if length <= window:
        yield 0, data
        return
    last_start = length - window
    offset = 0
    while offset < last_start:
        yield offset, data[offset:offset + window]
        offset += step
    # Final window is clamped to the end so trailing bytes are never skipped
    yield last_start, data[last_start:]


# Look for a known container signature near the start of a region
# The probe window is kept short so random bytes rarely trip a false name
def identify(blob, probe_limit=512):
    head = blob[:probe_limit]
    best = None
    for signature, name in MAGIC_SIGNATURES:
        index = head.find(signature)
        if index != -1 and (best is None or index < best[0]):
            best = (index, name)
    if best is None:
        return None
    return best[1]


# Group high-entropy windows into regions, tolerating one quiet window in a run
def scan_bytes(data, window=1024, step=128, threshold=7.5, min_region=1024):
    runs = []
    for offset, chunk in iter_windows(data, window, step):
        score = shannon_entropy(chunk)
        if score < threshold:
            continue
        start = offset
        end = offset + len(chunk)
        if runs and start <= runs[-1]["end"] + step:
            run = runs[-1]
            run["end"] = max(run["end"], end)
            run["peak"] = max(run["peak"], score)
        else:
            runs.append({"start": start, "end": end, "peak": score})

    found = []
    for run in runs:
        length = run["end"] - run["start"]
        if length < min_region:
            continue
        blob = data[run["start"]:run["end"]]
        found.append({
            "offset": run["start"],
            "length": length,
            "peak_entropy": round(run["peak"], 3),
            "mean_entropy": round(shannon_entropy(blob), 3),
            "format": identify(blob),
        })
    return found


# Render the findings as a fixed-width table
def format_table(path, regions, total):
    lines = []
    lines.append("file: %s (%d bytes)" % (path, total))
    if not regions:
        lines.append("no high-entropy regions found")
        return "\n".join(lines)
    lines.append("%-10s %-10s %-12s %-12s %s" % ("offset", "length", "peak", "mean", "format"))
    for region in regions:
        lines.append("%-10s %-10d %-12.3f %-12.3f %s" % (
            "0x%08x" % region["offset"],
            region["length"],
            region["peak_entropy"],
            region["mean_entropy"],
            region["format"] or "-",
        ))
    lines.append("%d region(s), %d bytes inside regions" % (
        len(regions),
        sum(r["length"] for r in regions),
    ))
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="entropy_scan",
        description="Locate high-entropy regions such as packed, encrypted or compressed payloads in a file.",
    )
    parser.add_argument("path", help="file to scan")
    parser.add_argument("--window", type=int, default=1024, help="window size in bytes (default 1024)")
    parser.add_argument("--step", type=int, default=128, help="window stride in bytes (default 128)")
    parser.add_argument("--threshold", type=float, default=7.5, help="entropy threshold in bits per byte (default 7.5)")
    parser.add_argument("--min-region", type=int, default=1024, help="discard regions shorter than this many bytes (default 1024)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--fail-on-hit", action="store_true", help="exit 3 when at least one region is found")
    parser.add_argument("--version", action="version", version="entropy_scan 1.0.0")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.window < 2:
        parser.error("--window must be at least 2")
    if args.step < 1:
        parser.error("--step must be at least 1")
    if args.min_region < 1:
        parser.error("--min-region must be at least 1")
    if not 0.0 < args.threshold <= 8.0:
        parser.error("--threshold must be above 0 and at most 8")

    try:
        with open(args.path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        print("entropy_scan: %s" % error, file=sys.stderr)
        return 2

    regions = scan_bytes(
        data,
        window=args.window,
        step=args.step,
        threshold=args.threshold,
        min_region=args.min_region,
    )

    if args.json:
        payload = {
            "path": args.path,
            "size": len(data),
            "window": args.window,
            "step": args.step,
            "threshold": args.threshold,
            "regions": regions,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_table(args.path, regions, len(data)))

    if args.fail_on_hit and regions:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
