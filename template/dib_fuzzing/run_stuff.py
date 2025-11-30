import subprocess
import os
import sys
import shlex

# --------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------
GDB = "gdb"
FUZZER = "./pdfium_fuzzer"   # your fuzzer binary
CORPUS_DIR = "./corpus"      # directory of PDFs
TIMEOUT = 300                # seconds per file
# --------------------------------------------------------

BREAKPOINTS = [
    "CPDF_DIB::CPDF_DIB",
    "CPDF_DIB::Load",
    "CPDF_DIB::LoadInternal",
    "CPDF_DIB::LoadColorInfo",
    "CPDF_DIB::StartLoadDIBBase",
    "CPDF_DIB::CreateDecoder",
    "CPDF_DIB::ContinueInternal",
    "CPDF_DIB::GetScanline",
    "CPDF_DIB::TranslateScanline24bpp",
    "CPDF_DIB::TranslateScanline24bppDefaultDecode"
]

def run_gdb_on_file(path):
    """Run gdb on one file and return True if breakpoint was hit."""
    script = ""

    # set breakpoints
    for bp in BREAKPOINTS:
        script += f"break {bp}\n"

    # run for TIMEOUT seconds
    script += f"set pagination off\n"
    script += f"set non-stop on\n"
    script += f"run \"{path}\"\n"
    # script += f"set confirm off\n"
    # script += f"quit\n"

    os.system(f"cp {path} ./input.bin")

    # Originally had  "--command=gdbscript.txt" too...

    gdb_cmd = [
        GDB, "--batch", "--command=gdbscript.txt", "--args", FUZZER, path
    ]

    print(" ".join(gdb_cmd))

    try:
        output = subprocess.check_output(
            gdb_cmd,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT # int(TIMEOUT)
        ).decode("utf-8", errors="replace")
        print("output: "+str(output))
    except subprocess.TimeoutExpired:
        print("FUCK")
        assert False
        return False, "timeout"
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8", errors="replace")

    # Did we hit any breakpoint?
    hit = "Breakpoint" in output or "breakpoint" in output
    return hit, output


def main():
    files = sorted(os.listdir(CORPUS_DIR))

    print(f"[+] Scanning {len(files)} PDF files for DIB activity...\n")
    for f in files:
        full = os.path.join(CORPUS_DIR, f)
        if not os.path.isfile(full):
            continue

        hit, out = run_gdb_on_file(full)
        if hit:
            print(f"\n\n🔥🔥🔥 BREAKPOINT HIT on file: {f} 🔥🔥🔥\n")
            print(out)

            # Save the result
            with open("DIB_HIT.txt", "a") as log:
                log.write(f"{f}\n")

            # Optional: stop immediately
            # sys.exit(0)

        else:
            print(f"[-] {f}: no DIB breakpoints")

    print("\n[+] Finished scanning corpus.")


if __name__ == "__main__":
    main()
