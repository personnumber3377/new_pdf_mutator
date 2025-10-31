#!/usr/bin/env python3
import os, time, hashlib
from pathlib import Path
import random

MUT_MAX_SLOTS = 256
BASE = Path(os.getenv("HOME")+str("/mut_ipc"))   # directory used for slot files
BASE.mkdir(exist_ok=True)

slot_input = None
slot_output = None
last_written_hash = None

def debug_log(string):
    fh = open(os.getenv("HOME")+"/mutator_log.log", "a+")
    fh.write(string)
    fh.write("\n")
    fh.close()
    return

def reserve_slot():
    """Find the first unused mut_inputX/mut_outputX pair."""
    global slot_input, slot_output

    # for i in range(1, MUT_MAX_SLOTS + 1):

    i = random.randrange(1_000_000_000)

    si = BASE / f"mut_input{i}"
    so = BASE / f"mut_output{i}"
    lock = BASE / f"mut_slot{i}.lock"

    '''
    try:
        # atomic slot acquisition
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        continue  # used by another mutator
    '''

    slot_input = si
    slot_output = so
    print(f"[mutator] acquired slot #{i}")
    return

    # raise RuntimeError("No free mut slot found (all taken)")


def init(seed: int):
    if slot_input is not None:
        return
    reserve_slot()


def fuzz_count(_buf: bytearray) -> int:
    """Always do 1 mutation step."""
    return 1


def wait_for_change(path: Path, previous_hash: str):
    """Busy-wait until file hash changes (not just timestamp)."""
    debug_log("Opening this file here: "+str(path.name))
    while True:
        if path.exists():
            data = path.read_bytes()
            h = hashlib.sha1(data).hexdigest()
            if True:
                return data, h
            # if h != previous_hash:
            #     return data, h
        time.sleep(0.001)  # avoid burning CPU


def custom_mutator(buf: bytearray, _addbuf, max_size: int, callback=None) -> bytearray:
    global last_written_hash

    init(0)

    # Dump input → file
    slot_input.write_bytes(buf)
    last_written_hash = hashlib.sha1(buf).hexdigest()

    # Block until external mutation is produced
    mutated_data, last_written_hash = wait_for_change(slot_output, last_written_hash)

    # Enforce max_size
    if len(mutated_data) > max_size:
        mutated_data = mutated_data[:max_size]

    return bytearray(mutated_data)
