# entropy-scan

Find the packed, encrypted or compressed chunks hiding inside a file. entropy-scan slides a window over the bytes, measures Shannon entropy for each window and merges the hot windows into regions you can look at with a hex editor.

Text and structured records sit around 4 to 5 bits per byte. Random data, compressed streams and encrypted payloads sit around 7.8 to 8.0. Anything between the two defaults is worth a second look.

## Usage

Run it against a single file:

```
python3 entropy_scan.py suspect.bin
```

Sample output:

```
file: suspect.bin (6144 bytes)
offset     length     peak         mean         format
0x00000800 4096       7.826        7.959        -
1 region(s), 4096 bytes inside regions
```

Ask for JSON when another tool needs to read the result:

```
python3 entropy_scan.py suspect.bin --json
```

Fail a pipeline when something turns up:

```
python3 entropy_scan.py suspect.bin --fail-on-hit
```

Exit codes are 0 for a completed scan, 2 when the file cannot be read and 3 when a region is found while `--fail-on-hit` is set.

## Options

- `--window N` sets the window size in bytes, default 1024. Smaller windows catch shorter payloads but score noisier.
- `--step N` sets the stride between windows, default 128. A step smaller than the window overlaps the samples and finds boundaries more precisely.
- `--threshold F` sets the entropy cutoff in bits per byte, default 7.5. Raise it to cut noise, lower it to catch lightly compressed data.
- `--min-region N` drops regions shorter than this many bytes, default 1024.
- `--json` prints a machine readable report instead of a table.
- `--fail-on-hit` returns exit code 3 when at least one region is found.

## Choosing a threshold

Window size changes the ceiling. A 1024 byte window of uniform random data averages about 7.80 bits per byte because small samples do not fill all 256 byte values evenly. A 256 byte window only averages about 7.18, so a 7.5 cutoff at that window size finds nothing at all. Keep the threshold below the measured ceiling for the window you picked, and check with a known compressed file before trusting a clean result.

## What the format column means

When a known container signature shows up within the first 512 bytes of a region, the report names it: gzip, zlib, xz, 7z, zip, rar, bzip2, lz4, zstd, an OpenSSL salted blob, png, jpeg or pdf. A dash means the data did not identify itself, which is normal for encrypted or custom packed payloads.

## Tests

```
python3 tests/test_entropy_scan.py
```

The suite covers the entropy maths, window coverage at the end of a buffer, locating an embedded random blob, dropping short regions, naming a zlib stream and the three command line exit paths.

## Limits

Entropy is a heuristic, not a classifier. Base64 and other text encodings of binary data score around 6 and land under the default cutoff. A payload smaller than `--min-region` is dropped on purpose. Regions start at the first window that crossed the threshold, so the reported offset can lead the real payload by up to one step.

## License

MIT, see LICENSE.
