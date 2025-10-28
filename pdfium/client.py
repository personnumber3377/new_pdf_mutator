#!/usr/bin/env python3
import time, hashlib
from pathlib import Path
# from mutator import fuzz   # ← your original fuzz(buf, add_buf, max_size)
import mutator
import random
import copy

BASE = Path("./mut_ipc")
SLOT_PREFIX = "mut_input"


def find_slot():
    """Find the slot this client should work on."""
    slots = sorted(BASE.glob(f"{SLOT_PREFIX}*"))
    if not slots:
        print("[client] No slot exists yet. Wait for mutator to start.")
        while not slots:
            slots = sorted(BASE.glob(f"{SLOT_PREFIX}*"))
            time.sleep(0.1)

    # we take the newest created slot
    slots.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    input_slot = slots[0]
    idx = input_slot.name.replace("mut_input", "")
    output_slot = BASE / f"mut_output{idx}"

    print(f"[client] attached to slot #{idx}")
    print(f"[client] input  → {input_slot}")
    print(f"[client] output → {output_slot}")

    return input_slot, output_slot


def wait_for_change(path: Path, previous_hash: str):
    """Wait until file content changes."""
    while True:
        if path.exists():
            data = path.read_bytes()
            h = hashlib.sha1(data).hexdigest()
            if h != previous_hash:
                return data, h
        time.sleep(0.001)


def main():
    input_slot, output_slot = find_slot()
    last_hash = ""
    mutator.init(random.randrange(100000)) # Initialize the stuff...
    while True:
        data, last_hash = wait_for_change(input_slot, last_hash)
        orig_data = copy.deepcopy(data)
        mutated = orig_data
        while mutated == orig_data:
            mutated = mutator.fuzz(bytearray(data), None, 10_000_000)  # your real mutator logic

        output_slot.write_bytes(mutated)
        print(f"[client] wrote mutated output ({len(mutated)} bytes)")


if __name__ == "__main__":
    main()