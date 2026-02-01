# v8-forensics

Detect V8 JavaScript engine exploitation artifacts in Chrome process memory dumps.

This work builds on research from the paper [Juicing V8: A Primary Account for the Memory Forensics of the V8 JavaScript Engine](https://www.sciencedirect.com/science/article/pii/S2666281722000816), which first demonstrated symbol-less V8 object extraction, so a big thanks to the following authors for laying the groundwork that made this tool possible:

- Enoch Wang
- Smuel Zurowski
- Orion Duffy
- Tyler Thomas
- Ibrahim Baggili

## What it does

Scans Chrome renderer minidumps for heap corruption patterns that indicate active or attempted exploitation:

- **Corrupted array lengths** - `JSArray.length > elements.length`
- **Elements kind mismatches** - Map's ElementsKind doesn't match backing store type
- **Embedded fake objects** - JSArray headers inside another array's backing store

These patterns violate V8 invariants and don't occur during normal JavaScript execution.

## Install

```bash
git clone https://github.com/user/v8-forensics
cd v8-forensics
cargo build --release
```

## Usage

```
v8-forensics <dump.dmp>

--stats     Show heap statistics
--json      Output as JSON
--verbose   Show detailed analysis
```

Example output:

```
loading dump: "example.dmp"
loaded 818 regions (2564.8 MB)

arrays with corrupted length (array_length > elements_length):

  corrupted array 1:
    address: 0x3a0002ccd4c
    map_address: 0x3a00010e449 (instance_type: 2119)
    elements_kind: 4
    array_length: 128 (CORRUPTED)
    elements_length: 2
    oob_elements: 126

fake arrays embedded in other arrays:

  embedded array 1:
    address: 0x3a0002ccd4c
    map_address: 0x3a00010e449 (instance_type: 2119)
    elements_kind: 4
    array_length: 128
    elements_length: 2
    elements_address: 0x3a0002ccd45
    elements_map_address: 0x3a0000008a1
    container_address: 0x3a0002ccd28
    container.array_length: 2
    container.elements_length: 2
    container.elements_address: 0x3a0002ccd45
    offset: 8 bytes (element ~0)

elements map mismatches detected:

  mismatch 1:
    address: 0x3a0002ccdd8
    map_address: 0x3a00010e449 (instance_type: 2119)
    elements_kind: 4
    array_length: 4
    elements_length: 0
    elements_address: 0x3a0002ccf71
    elements_map_address: 0x1
```

## Reproduction

Host the files in `./repro` using `python3 -m http.server --bind 127.0.0.1 8080` then download Chrome stable release `134.0.6998.36` for Windows, install it, then execute the following:

```
chrome.exe --renderer-process-limit=1 --disable-crash-reporter --enable-logging=stderr --no-sandbox --user-data-dir=data http://127.0.0.1:8080/index.html
```

## How it works

1. Locates the MetaMap (the only V8 object where object.map == object)
2. Derives the cage base from MetaMap's address
3. Finds all Map objects (they point to MetaMap)
4. Finds all JSArrays by scanning for valid Map pointers

5. Validates each array against V8's structural invariants
