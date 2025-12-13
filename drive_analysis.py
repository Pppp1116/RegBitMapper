# coding: utf-8
"""
drive_analysis.py

Wrapper around PyGhidra/Ghidra headless analysis + RegistryKeyBitfieldReport.py.

- Opens/imports a target binary into a Ghidra project
- Applies analysis options (the "original" option set + any CLI overrides)
- Runs Ghidra auto-analysis
- Executes RegistryKeyBitfieldReport.py in-process so it sees currentProgram/getScriptArgs
- Writes NDJSON (stdout of RegistryKeyBitfieldReport) to a file
"""

from __future__ import annotations

import argparse
import inspect
import io
import os
import runpy
import sys
import warnings
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr


# "Original" analyzer option set (9 entries).
# Note: Ghidra 12 builds differ: some expose "Aggressive Instruction Finder", others "Aggressive Instruction Search".
# We include BOTH so whichever exists gets applied.
DEFAULT_ANALYSIS_OPTIONS: dict[str, str] = {
    "Decompiler Parameter ID": "true",
    "Stack": "true",
    "Data Reference": "true",
    "ASCII Strings": "true",
    "Embedded Media": "true",
    "Reference": "true",
    "Variadic Function Signature Override": "true",
    "Aggressive Instruction Finder": "true",
    "Aggressive Instruction Search": "true",
}


def _truthy_str(v: str) -> str:
    s = (v or "").strip().lower()
    if s in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
        return "true"
    if s in {"0", "false", "no", "n", "off", "disable", "disabled"}:
        return "false"
    raise ValueError(f"Bad boolean value: {v!r} (use true/false)")


def _parse_analysis_kv(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise ValueError(f'Bad --analysis value {raw!r}. Expected: "Option Name=true|false"')
    name, val = raw.split("=", 1)
    name = name.strip()
    val = _truthy_str(val)
    if not name:
        raise ValueError(f"Bad --analysis value {raw!r} (empty option name)")
    return name, val


def _resolve_path_maybe_relative(p: str) -> Path:
    pp = Path(p).expanduser()
    if pp.is_absolute():
        return pp
    # default relative to the drive_analysis.py location
    return (Path(__file__).resolve().parent / pp).resolve()


class _Tee(io.TextIOBase):
    def __init__(self, *streams: io.TextIOBase):
        super().__init__()
        self._streams = streams

    def write(self, s: str) -> int:
        for st in self._streams:
            st.write(s)
        return len(s)

    def flush(self) -> None:
        for st in self._streams:
            st.flush()


def _open_program_compat(pyghidra_mod, target: str, project_path: str, project_name: str, analyze: bool, options: dict[str, str]):
    """
    open_program() has moved/changed signatures across pyghidra versions.
    This helper adapts to common variants.
    """
    open_program = pyghidra_mod.open_program
    sig = inspect.signature(open_program)
    kwargs = {}

    # project path kw name
    if "project_location" in sig.parameters:
        kwargs["project_location"] = project_path
    elif "project_path" in sig.parameters:
        kwargs["project_path"] = project_path
    elif "project" in sig.parameters:
        kwargs["project"] = project_path

    if "project_name" in sig.parameters:
        kwargs["project_name"] = project_name

    if "analyze" in sig.parameters:
        kwargs["analyze"] = analyze

    # analysis options kw name varies
    if options:
        if "options" in sig.parameters:
            kwargs["options"] = options
        elif "analysis_options" in sig.parameters:
            kwargs["analysis_options"] = options
        # else: not supported on this pyghidra version

    return open_program(target, **kwargs)


def _run_report_inprocess(script_path: Path, program, script_args: list[str], out_ndjson: Path, log_path: Path) -> int:
    out_ndjson.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # RegistryKeyBitfieldReport emits NDJSON via stdout.
    # We redirect stdout to a file so it never gets swallowed/captured by pyghidra wrappers.
    with out_ndjson.open("w", encoding="utf-8", newline="\n") as f_out, log_path.open("w", encoding="utf-8", buffering=1) as f_log:
        tee_err = _Tee(sys.stderr, f_log)

        init_globals = {
            # Make it look like a real Ghidra Script Manager run
            "currentProgram": program,
            "getScriptArgs": (lambda: list(script_args)),
        }

        try:
            with redirect_stdout(f_out), redirect_stderr(tee_err):
                runpy.run_path(str(script_path), run_name="__main__", init_globals=init_globals)
            return 0
        except SystemExit as e:
            code = e.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            return 1
        except Exception:
            import traceback
            traceback.print_exc(file=tee_err)
            return 1


def analyze_target(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="drive_analysis.py",
        add_help=True,
        description="Run Ghidra analysis with specific analyzer options, then run RegistryKeyBitfieldReport.py and save NDJSON.",
    )
    parser.add_argument("--target", default=os.environ.get("GHIDRA_TARGET_BINARY") or r"C:\Users\Pppp1116\Desktop\target_O3_sections.exe")
    parser.add_argument("--project-path", default=os.environ.get("GHIDRA_PROJECT_PATH") or r"C:\GhidraProjects")
    parser.add_argument("--project-name", default=os.environ.get("GHIDRA_PROJECT_NAME") or "O3_Analysis_Fixed")
    parser.add_argument("--script", default=os.environ.get("GHIDRA_REPORT_SCRIPT") or r"C:\Users\Pppp1116\Downloads\RegistryKeyBitfieldReport.py")
    parser.add_argument("--analysis", action="append", default=[], help='Repeatable. Example: --analysis "Decompiler Parameter ID=true"')
    parser.add_argument("--no-analyze", action="store_true", help="Skip Ghidra auto-analysis/analyzeAll()")
    parser.add_argument("--out", default="", help="Path to write NDJSON output (default: <cwd>/<target>.regbit.ndjson)")
    parser.add_argument("--log", default="", help="Path to write stderr log (default: <out>.log)")

    # Everything unknown becomes script args (mode=..., debug=..., trace=..., etc.)
    args_ns, script_kv = parser.parse_known_args(argv)

    target = str(_resolve_path_maybe_relative(args_ns.target))
    project_path = str(_resolve_path_maybe_relative(args_ns.project_path))
    project_name = str(args_ns.project_name)
    script_path = _resolve_path_maybe_relative(args_ns.script)

    if not args_ns.out:
        out_ndjson = Path.cwd() / (Path(target).stem + ".regbit.ndjson")
    else:
        out_ndjson = _resolve_path_maybe_relative(args_ns.out)

    if not args_ns.log:
        log_path = Path(str(out_ndjson) + ".log")
    else:
        log_path = _resolve_path_maybe_relative(args_ns.log)

    analysis_options = dict(DEFAULT_ANALYSIS_OPTIONS)
    for raw in args_ns.analysis:
        name, val = _parse_analysis_kv(raw)
        analysis_options[name] = val

        # keep the Finder/Search aliases aligned if user set either one
        if name == "Aggressive Instruction Finder":
            analysis_options["Aggressive Instruction Search"] = val
        if name == "Aggressive Instruction Search":
            analysis_options["Aggressive Instruction Finder"] = val

    # Reduce Python-side noise (doesn't affect Java warnings)
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    print("[+] Initializing Ghidra Context...")
    print(f"[+] Target: {target}")
    print(f"[+] Project: {Path(project_path) / project_name}")
    print(f"[+] Script: {script_path}")
    print(f"[+] Analysis options: {len(analysis_options)}")
    print(f"[+] Script args: {' '.join(script_kv) if script_kv else '(none)'}")

    import pyghidra  # import only when needed

    try:
        ctx = _open_program_compat(
            pyghidra,
            target=target,
            project_path=project_path,
            project_name=project_name,
            analyze=(not args_ns.no_analyze),
            options=analysis_options,
        )
    except TypeError as e:
        # Older pyghidra: no options kw, etc.
        print(f"[!] open_program signature mismatch; retrying without analysis options: {e}", file=sys.stderr)
        ctx = _open_program_compat(
            pyghidra,
            target=target,
            project_path=project_path,
            project_name=project_name,
            analyze=(not args_ns.no_analyze),
            options={},
        )

    with ctx as flat_api:
        program = flat_api.getCurrentProgram()
        print(f"[+] Program Mounted: {program.getName()}")

        if not args_ns.no_analyze:
            print("[+] Running analyzeAll()...")
            try:
                flat_api.analyzeAll(program)
            except Exception:
                # Some versions expose analyzeAll() without args
                try:
                    flat_api.analyzeAll()
                except Exception:
                    import traceback
                    print("[!] analyzeAll() failed (continuing):", file=sys.stderr)
                    traceback.print_exc()

        try:
            fm = program.getFunctionManager()
            fn_count = sum(1 for _ in fm.getFunctions(True))
        except Exception:
            fn_count = -1
        if fn_count >= 0:
            print(f"[+] Functions identified: {fn_count}")

        print(f"[+] Running RegistryKeyBitfieldReport and writing NDJSON -> {out_ndjson}")
        rc = _run_report_inprocess(script_path, program, script_kv, out_ndjson, log_path)
        if rc != 0:
            print(f"[!] Report script exited with code {rc}. Stderr log: {log_path}", file=sys.stderr)
            return rc

    print(f"[+] Done. NDJSON: {out_ndjson} | log: {log_path}")
    return 0


def main() -> int:
    return analyze_target(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
