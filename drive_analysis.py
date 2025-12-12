# drive_analysis.py
# Implements the remediation strategy to ensure correct analysis settings
# for optimized (-O3) binaries and uses the fixed RegistryKeyBitfieldReport.
import os
import sys

from pyghidra import ghidra_script, open_program


def analyze_target() -> None:
    # CONFIGURATION
    target_file = r"C:\\Users\\Pppp1116\\Desktop\\target_O3_sections.exe"  # UPDATE THIS PATH
    script_file = r"RegistryKeyBitfieldReport.py"  # Ensure this is in the same folder
    project_location = r"C:\\GhidraProjects"
    project_name = "O3_Analysis_Fixed"

    # CRITICAL: These options fix the optimization analysis issues
    analysis_options = {
        "Decompiler Parameter ID": "true",  # Required for -O3 custom calling conventions
        "Stack": "true",
        "Data Reference": "true",
    }

    print("[+] Initializing Ghidra 12.0 Context...")

    # Use open_program as a context manager to handle the lifecycle
    with open_program(
        target_file,
        project_location=project_location,
        project_name=project_name,
        analyze=True,
        options=analysis_options,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        print(f"[+] Program Mounted: {program.getName()}")

        # Verify auto-analysis is complete
        func_count = program.getFunctionManager().getFunctionCount()
        print(f"[+] Functions identified: {func_count}")

        # Inject the fixed logic script
        print(f"[+] Running {script_file}...")

        # Pass the analysis arguments required by your script
        script_args = ["mode=taint", "debug=true", "trace=true"]

        # Execute
        ghidra_script(script_file, flat_api.getGhidraProject(), args=script_args)


if __name__ == "__main__":
    analyze_target()
