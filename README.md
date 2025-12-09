# RegBitMapper

RegistryKeyBitfieldReport is a Ghidra/PyGhidra script that discovers Windows registry key usage across a program and emits bitfield-oriented reports. It can run inside the Ghidra Script Manager or headlessly via PyGhidra while keeping backward-compatible NDJSON output alongside a Markdown summary.

## Requirements
- Ghidra with the script placed in your `ghidra_scripts` directory (for UI execution)
- Python 3 with [`pyghidra`](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Extensions/Python) available on the path (for headless use)
- Access to the target binary you want to analyze
- The script declares `#@category RegBitMapper` and `#@runtime Jython` so the Ghidra 12 Script Manager categorizes it correctly and runs it under Jython

## Running inside the Ghidra UI
1. Copy `RegistryKeyBitfieldReport.py` into your Ghidra `ghidra_scripts` directory.
2. Open the target program in Ghidra 12 (or later).
3. Launch the script from the Script Manager. The script will automatically use the active program; no CLI arguments are needed.
4. Optional: supply script arguments (e.g., `depth=128 debug=true output_dir=/tmp/report`) via the Script Manager arguments field to override defaults.

## Running with `analyzeHeadless` (Ghidra 12)
- Place the script in your `ghidra_scripts` directory or pass `-scriptPath` to include its location.
- Invoke `analyzeHeadless` with your project/workspace and target binary, then post-run the script:

```bash
analyzeHeadless /tmp/ghidra-project MyProject \
  -import /path/to/sample.bin \
  -postScript RegistryKeyBitfieldReport.py depth=128 output_dir=/tmp/regbitmapper debug=true
```

The script consumes `getScriptArgs` provided by Ghidra, so key/value pairs supplied after the script name override defaults identically to Script Manager usage.

## Headless / PyGhidra usage
Invoke the script directly with Python, providing the path to the binary and any optional arguments:

```bash
python RegistryKeyBitfieldReport.py <binary> [options]
```

### Arguments
- `binary` (positional, required headlessly): Path to the binary to analyze.
- `--depth DEPTH` (default: 256): Maximum call depth to explore when tracing registry usage.
- `--debug`: Print high-level progress messages.
- `--debug-trace`: Emit verbose trace logging.
- `--output-dir OUTPUT_DIR`: Destination directory for generated reports. Defaults to `~/regkeys/<program-name>`.
- `--additional-apis ADDITIONAL_APIS`: Regex to extend the built-in registry API patterns (e.g., `--additional-apis "Zw.*Key"`).

### Example
```bash
python RegistryKeyBitfieldReport.py /path/to/sample.bin \
  --depth 128 \
  --output-dir /tmp/regbitmapper \
  --additional-apis "Zw.*Key" \
  --debug
```

## Output
Two files are written to the output directory (default `~/regkeys/<program-name>`):
- `<program>.registry_bitfields.ndjson`: NDJSON records for each discovered registry key, including API call sites and decision points.
- `<program>.registry_bitfields.md`: Human-readable Markdown summary of the same data.

## Notes
- When run from the Ghidra UI, the script bypasses CLI parsing and instead uses the currently active program.
- Errors writing output files are logged when `--debug` is enabled.
