#!/usr/bin/env python3
"""
mutator.py -- AFL++ Python custom mutator for PDF structural mutations.

Features:
 - Deterministic mutation decisions derived from the input bytes (no global RNG).
 - Loads a corpus of resource-like dictionaries from a PDF directory or a cached resources.pkl.
 - Mutation actions:
     * replace an entire object (Stream or Dictionary) with a sample from the resources DB
     * or mutate an object in-place (dictionary / stream) using type-aware modifications
     * or shuffle pages
 - Keeps a small header (HEADER_SIZE) unchanged.
 - Raises on conversion failures (no silent fallback to generic byte-level mutations).
 - Exposes AFL++ interface: init(seed), deinit(), fuzz_count(buf), fuzz(buf, add_buf, max_size).

Environment:
 - MUTATOR_PDF_DIR  : dir with sample PDFs to build resources DB (default ./pdf_seed_corpus/)
 - MUTATOR_PKL_PATH : path to pickle DB (default ./resources.pkl)
"""

from __future__ import annotations

import traceback
import os
import io
import sys
import pickle
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple
import random
import traceback
import generic_mutator_bytes
import copy
import datetime
import decimal

sys.setrecursionlimit(20000)


def dlog(string):
    with open("custom_mutator.log", "a") as log:
        log.write(f"custom_mutator exception: {string}\n")

try:
    import pikepdf
    from pikepdf import Name, Dictionary, Array, Stream, Object
except Exception as e:
    print("ERROR: pikepdf required. Install: pip3 install pikepdf", file=sys.stderr)
    raise

# -----------------------------
# For debugging
# -----------------------------

# DEBUG = False

DEBUG = True

def dprint(msg: str) -> None:
    if DEBUG:
        print("[DEBUG] "+str(msg))
    return

# -----------------------------
# Config / Globals
# -----------------------------
# HEADER_SIZE = 4  # keep header bytes unchanged in mutated output
HEADER_SIZE = 0 # Zero byte header...
DEFAULT_MUTATION_COUNT = 100
MAX_DB_SIZE = 30000
MAX_CALL_COUNT = 200000

MAX_DRAW_OPERATIONS = 10

MAX_STRING_SIZE = 10000
MAX_STRING_MULT_COUNT = 1000

MAX_DA_MUTATION_STEPS = 10

SCALE_STUFF = 10.0

MAX_MUTATIONS = 20

not_reached = True # This is the thing

MAX_CHAR_INSERT_COUNT = 10000 # Add some characters...

PDF_DRAWING_OPS = [
    # Path construction
    "m", "l", "c", "v", "y", "h", "re",

    # Painting
    "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n",

    # Text
    "BT", "ET", "Tf", "Td", "TD", "Tm", "Tj", "TJ", "'", '"',

    # Graphics state
    "q", "Q", "cm", "w", "J", "j", "M", "d", "ri",

    # Color
    "rg", "RG", "k", "K", "g", "G",

    # XObject/image
    "Do"
]


HARD_CODED_STRINGS = [
    "FUZZ-HELLO",
    "😈 fuzzed string",
    "pikepdf-mutator",
    "AAAAAAAAAAAA",
    "🔥 fuzz fuzz fuzz 🔥",
]

MAX_INTEGER_RANGE = 2**32 - 1

BANNED_KEYS = set(["/Length", "/Kids"])  # Do not modify these on stream dicts
MAX_RECURSION = 8

# MAX_32_INT = 2**31 - 1

MAX_32_INT = 1000000

def clamp_int_32(integer: int) -> int: # Clamps integer to the thing...
    dprint("fefeeeeeeeeeeeeeee")
    if integer <= -MAX_32_INT:
        integer = -MAX_32_INT
    elif integer >= MAX_32_INT:
        integer = MAX_32_INT
    dprint("returning this integer: "+str(integer))
    return integer

MAX_SCALE_FACTOR = 10000000000.0 # The max float scale factor

MAX_INTEGER_THING = 10000000

DEFAULT_PDF_DIR = Path(os.environ.get("MUTATOR_PDF_DIR", "./pdf_seed_corpus/"))
DEFAULT_PKL_PATH = Path(os.environ.get("MUTATOR_PKL_PATH", "./resources.pkl"))

_mutation_count = DEFAULT_MUTATION_COUNT
_initialized = False
_resources_db: List[Dict[str, Any]] = []  # python-serializable resource dict samples
_call_counter = 0

# -----------------------------
# Type map (for guided dict edits)
# -----------------------------
DICT_TYPE_MAP = {
    "LW": "number", "LC": "int", "LJ": "int", "ML": "number",
    "D": "array", "RI": "name", "OP": "bool", "op": "bool",
    "OPM": "int", "BG": "any", "BG2": "any", # This also had Font in it as an array, but that is not accurate.
    "UCR": "any", "UCR2": "any", "TR": "any", "TR2": "any",
    "FL": "number", "SM": "number", "SA": "bool",
    "BM": "name", "SMask": "dict", "CA": "number", "ca": "number",
    "AIS": "bool", "TK": "bool",
    "Frequency": "number", "Angle": "number", "SpotFunction": "any",
    "AccurateScreens": "bool", "HalftoneType": "int",
    "Width": "int", "Height": "int", "Width2": "int", "Height2": "int",
    "Xsquare": "int", "Ysquare": "int",
    "FontDescriptor": "dict", "BaseFont": "name", "DW": "number",
    "DW2": "array", "W": "array", "W2": "array", "CIDToGIDMap": "any",
    "CIDSystemInfo": "dict", "Registry": "string", "Ordering": "string",
    "Supplement": "int", "Flags": "int", "FontBBox": "array",
    "FontMatrix": "array", "Encoding": "any", "ToUnicode": "any",
    "FontName": "name", "StemV": "int", "XHeight": "int", "CapHeight": "int",
    "Ascent": "int", "Descent": "int", "AvgWidth": "int", "MaxWidth": "int",
    "ItalicAngle": "number", "Leading": "int", "MissingWidth": "int",
    "DecodeParms": "dict", "Filter": "name", "SMaskInData": "int",
    "Interpolate": "bool", "ImageMask": "bool",
    "MediaBox": "array", "CropBox": "array", "Rotate": "int",
    "UserUnit": "number", "Resources": "dict", "Annots": "array",
    "FunctionType": "int", "Order": "int", "BitsPerSample": "int",
    "Functions": "array", "Size": "int", "Index": "array", "Prev": "int",
    "Producer": "string", "Creator": "string", "Author": "string",
    "Title": "string", "Subject": "string", "Keywords": "string",
}

import random
from typing import Optional

from pikepdf import Pdf, Stream, Matrix
from pikepdf.canvas import Canvas, Color

from pikepdf._core import AttachedFileSpec
from pikepdf.models.image import PdfImage
from pikepdf.form import Form

from pikepdf import Pdf, Stream, parse_content_stream
from pikepdf.canvas import Canvas, ContentStreamBuilder, Text, Helvetica, Matrix
import random

def _random_low_level_ops(cs: ContentStreamBuilder, width, height, rng):
    """Adds random low-level PDF operators using ContentStreamBuilder."""

    ops = rng.randint(1, 50)

    for _ in range(ops):
        r = rng.random()

        if r < 0.1:
            cs.push()

        elif r < 0.2:
            cs.pop()

        elif r < 0.3:
            # Random concat matrix
            a = rng.uniform(-1, 1)
            d = rng.uniform(-1, 1)
            e = rng.uniform(0, width)
            f = rng.uniform(0, height)
            m = Matrix(a, 0, 0, d, e, f)
            cs.cm(m)

        elif r < 0.45:
            # Rectangle
            x = rng.uniform(0, width)
            y = rng.uniform(0, height)
            w = rng.uniform(5, width / 2)
            h = rng.uniform(5, height / 2)
            cs.append_rectangle(x, y, w, h)
            if rng.random() < 0.5:
                cs.fill()
            else:
                cs.stroke_and_close()

        elif r < 0.6:
            # Line
            x1 = rng.uniform(0, width)
            y1 = rng.uniform(0, height)
            x2 = rng.uniform(0, width)
            y2 = rng.uniform(0, height)
            cs.line(x1, y1, x2, y2)
            cs.stroke_and_close()

        elif r < 0.7:
            # Dashes: correct usage
            dash = rng.uniform(0.5, 20)
            gap = rng.uniform(0.5, 20)
            phase = int(rng.uniform(0, 10))
            cs.set_dashes([dash, gap], phase)

        elif r < 0.85:
            # Marked content
            cs.begin_marked_content(Name("/MC"))
            cs.end_marked_content()

        else:
            # Text drawing
            cs.begin_text()
            cs.set_text_font(Name.Helvetica, rng.uniform(6, 24))
            cs.set_text_matrix(Matrix(1, 0, 0, 1,
                                      rng.uniform(0, width),
                                      rng.uniform(0, height)))
            text = f"rnd {rng.randint(0, 9999)}".encode("utf-16be")
            cs.show_text(text)
            cs.end_text()

def insert_random_colorspace_image(pdf, rng=None):
    if rng is None:
        rng = random.Random()

    page = pdf.pages[0]

    # Select a random colorspace type
    cs_type = rng.choice([
        "DeviceGray",
        "DeviceRGB",
        "DeviceCMYK",
        "CalGray",
        "CalRGB",
        "Lab",
        "ICCBased",
        "Indexed",
        "Separation",
        "DeviceN",
    ])

    dprint("We picked this random colorspace stuff: "+str(cs_type))

    # Very small demo image 8×8
    width = rng.randrange(1,10) # 8
    height = rng.randrange(1,10) # 8

    # Generate raw image bytes (just random noise)
    raw_bytes = bytes(rng.getrandbits(8) for _ in range(width * height * 4))

    #
    # Build ColorSpace dictionary
    #
    if cs_type == "DeviceGray":
        colorspace = Name.DeviceGray

    elif cs_type == "DeviceRGB":
        colorspace = Name.DeviceRGB

    elif cs_type == "DeviceCMYK":
        colorspace = Name.DeviceCMYK

    elif cs_type == "CalGray":
        colorspace = Array([
            Name.CalGray,
            Dictionary({
                '/WhitePoint': Array([1.0, 1.0, 1.0]),
                # Name.WhitePoint: Array([1.0, 1.0, 1.0]),
            })
        ])

    elif cs_type == "CalRGB":
        colorspace = Array([
            Name.CalRGB,
            Dictionary({
                '/WhitePoint': Array([1.0, 1.0, 1.0]),
            })
        ])

    elif cs_type == "Lab":
        colorspace = Array([
            Name.Lab,
            Dictionary({
                '/WhitePoint': Array([1.0, 1.0, 1.0]),
                '/Range': Array([-128, 127, -128, 127]),
            })
        ])

    elif cs_type == "ICCBased":
        # Minimal fake ICC profile (PDF accepts it)
        icc_stream = pdf.make_stream(b"\x00" * 128)
        icc_stream.N = 3
        colorspace = Array([Name.ICCBased, icc_stream])

    elif cs_type == "Indexed":
        hival = 3
        palette = bytes(rng.getrandbits(8) for _ in range((hival+1) * 3))
        colorspace = Array([Name.Indexed, Name.DeviceRGB, hival, palette])

    elif cs_type == "Separation":
        tint_func = pdf.make_stream(b"{0 exch 1 exch sub}")
        tint_func.FunctionType = 4
        tint_func.Domain = [0, 1]
        tint_func.Range = [0, 1, 0, 1, 0, 1, 0, 1]
        colorspace = Array([
            Name.Separation,
            Name("/SpotGreen"),
            Name.DeviceCMYK,
            tint_func,
        ])

    elif cs_type == "DeviceN":
        tint_func = pdf.make_stream(b"{0 0 0 4 -1 roll}")
        tint_func.FunctionType = 4
        tint_func.Domain = [0, 1]
        tint_func.Range = [0, 1, 0, 1, 0, 1, 0, 1]
        colorspace = Array([
            Name.DeviceN,
            Array([Name.Black]),
            Name.DeviceCMYK,
            tint_func,
        ])

    else:
        return  # should never happen

    #
    # Build image XObject
    #
    im_obj = Stream(
        pdf,
        raw_bytes,
        Width=width,
        Height=height,
        BitsPerComponent=8,
        ColorSpace=colorspace,
        Subtype=Name.Image,
        Type=Name.XObject,
    )

    # Attach to page Resources
    res = page.Resources
    if "/XObject" not in res:
        # res["XObject"] = Dictionary()
        res[Name.XObject] = Dictionary()

    name = Name(f"/Im{len(res.XObject)}")
    res.XObject[name] = im_obj

    # Draw the image
    page_content = f"100 0 0 100 50 50 cm /{name} Do".encode("ascii")
    if page.Contents is None:
        page.Contents = pdf.make_stream(page_content)
    else:
        # existing = page.Contents.read_bytes()
        # page.Contents = pdf.make_stream(existing + b"\n" + page_content)
        page.Contents = pdf.make_stream(page_content)

def overlay_random_canvas(pdf: Pdf, *, max_operations=MAX_DRAW_OPERATIONS, rng=None):
    """
    Modify the existing content streams of each page by APPENDING
    new Canvas + raw ContentStreamBuilder operations.
    """
    if rng is None:
        rng = random.Random()

    for page in pdf.pages:

        # Determine page width/height from MediaBox
        try:
            mb = page.MediaBox
            width = float(mb[2] - mb[0])
            height = float(mb[3] - mb[1])
        except Exception:
            width, height = 612.0, 792.0

        #
        # Create a Canvas matching page size — this DOES NOT overwrite anything.
        #
        canvas = Canvas(page_size=(width, height))

        # High-level operations from your previous mutator
        n_ops = rng.randint(0, max_operations)
        for _ in range(n_ops):
            r = rng.random()
            if r < 0.20:
                _random_stack_and_transform(canvas, rng)
            elif r < 0.45:
                _random_rect(canvas, width, height, rng)
            elif r < 0.75:
                _random_line(canvas, width, height, rng)
            else:
                _random_color_change(canvas, rng)

        #
        # ★ New: ADD low-level ContentStreamBuilder mutations directly.
        #
        builder = ContentStreamBuilder()

        # Add random low-level ops
        _random_low_level_ops(builder, width, height, rng)

        # Add the builder’s bytes into the Canvas *before* exporting.
        canvas._cs.extend(builder.build())

        #
        # Convert the Canvas → PDF, *extract just the content stream*.
        #
        overlay_pdf = canvas.to_pdf()
        overlay_page = overlay_pdf.pages[0]
        overlay_bytes = overlay_page.Contents.read_bytes()

        #
        # Merge into existing page content stream
        #

        # Select random drawing operation stream to append stuff...

        dprint("page: "+str(page))
        if "/Contents" in page: # Check the thing...
            dprint("Yes the contents are here: "+str(page["/Contents"]))
        conts = page["/Contents"] # Do the stuff...
        dprint("conts: "+str(conts))
        if conts == None:
            return # No content, so return
        # Now select random stream...
        if isinstance(conts, Stream):
            rand_stream = conts # It already is a stream
        else:
            rand_stream = rng.choice(conts)

        dprint("Here is the rand_stream: "+str(rand_stream))
        
        orig = rand_stream.read_bytes() # Read the stuff.
        dprint("Here is the original data: "+str(orig))
        # read_bytes()

        '''
        try:
            dprint("Here is the instance of the thing: "+str(type(page.Contents)))
            dprint("Here is the actual value of page.Contents: "+str(page.Contents))
            orig = page.Contents.read_bytes() if page.Contents else b""
        except Exception as e:
            dprint("Some exception occurred when reading stream: "+str(e))
            orig = b""
        '''

        if orig == b"":
            dprint("the stream is not supposed to be empty...")

        merged = orig + b"\n" + overlay_bytes
        page.Contents = Stream(pdf, merged)
        dprint("Succesfully entered the stuff!!!")


def _random_stack_and_transform(canvas: Canvas, rng: random.Random) -> None:
    """
    Randomly push/pop the graphics state and apply a simple transform.

    We always wrap transforms in a save_state context so that any insane CTM
    doesn't permanently corrupt subsequent operations.
    """
    # Random small scaling and translation
    sx = 0.1 + rng.random() * MAX_SCALE_FACTOR
    sy = 0.1 + rng.random() * MAX_SCALE_FACTOR
    tx = -50.0 + rng.random() * MAX_SCALE_FACTOR
    ty = -50.0 + rng.random() * MAX_SCALE_FACTOR

    m = Matrix().scaled(sx, sy).translated(tx, ty)

    # 50% of the time: use a context manager (q/Q)
    # 50%: just push/pop explicitly (still safe)
    if rng.random() < 0.5:
        with canvas.do.save_state(cm=m):
            # Optionally draw a simple primitive inside
            if rng.random() < 0.5:
                # Tiny line inside transformed state
                canvas.do.line(0, 0, rng.random() * MAX_SCALE_FACTOR, rng.random() * MAX_SCALE_FACTOR)
            else:
                # Tiny rect
                canvas.do.rect(0, 0, rng.random() * MAX_SCALE_FACTOR, rng.random() * MAX_SCALE_FACTOR, fill=False)
    else:
        canvas.do.push()
        canvas.do.cm(m)
        if rng.random() < 0.5:
            canvas.do.line(0, 0, rng.random() * MAX_SCALE_FACTOR, rng.random() * MAX_SCALE_FACTOR)
        else:
            canvas.do.rect(0, 0, rng.random() * MAX_SCALE_FACTOR, rng.random() * MAX_SCALE_FACTOR, fill=True)
        canvas.do.pop()


def _random_rect(
    canvas: Canvas,
    width: float,
    height: float,
    rng: random.Random,
) -> None:
    """
    Draw a random rectangle (filled, stroked, or both) within the page bounds.
    """
    # Random rect position and size (clamped to page)
    w = rng.random() * width * 0.5 + 1.0
    h = rng.random() * height * 0.5 + 1.0
    x = rng.random() * max(width - w, 1.0)
    y = rng.random() * max(height - h, 1.0)

    # Randomly tweak line width occasionally
    if rng.random() < 0.3:
        lw = 0.1 + rng.random() * 10.0
        canvas.do.line_width(lw)

    # Maybe change stroke/fill color before drawing
    if rng.random() < 0.5:
        _random_color_change(canvas, rng)

    fill_mode = rng.random()
    if fill_mode < 0.33:
        # stroke only
        canvas.do.rect(x, y, w, h, fill=False)
    elif fill_mode < 0.66:
        # fill only
        canvas.do.rect(x, y, w, h, fill=True)
    else:
        # fill and stroke: fill then stroke the same rect
        canvas.do.rect(x, y, w, h, fill=True)
        canvas.do.rect(x, y, w, h, fill=False)


def _random_line(
    canvas: Canvas,
    width: float,
    height: float,
    rng: random.Random,
) -> None:
    """
    Draw a random line segment across the page.
    """
    x1 = rng.random() * width
    y1 = rng.random() * height
    x2 = rng.random() * width
    y2 = rng.random() * height

    # Randomly choose dashes or solid
    if rng.random() < 0.3:
        if rng.random() < 0.5:
            canvas.do.dashes()  # clear dashes
        else:
            dash_len = rng.random() * MAX_SCALE_FACTOR + 1
            gap_len = rng.random() * MAX_SCALE_FACTOR + 1
            phase = int(rng.random() * MAX_SCALE_FACTOR)
            # canvas.do.dashes(dash_len, gap_len, phase)
            canvas.do.dashes(1, 1)

    # Maybe change stroke color
    if rng.random() < 0.5:
        _random_color_change(canvas, rng, stroke_only=True)

    canvas.do.line(x1, y1, x2, y2)


def _random_color_change(
    canvas: Canvas,
    rng: random.Random,
    *,
    stroke_only: bool = False,
) -> None:
    """
    Randomly change stroke and/or fill colors using device RGB.

    Uses pikepdf.canvas.Color(r, g, b, a) with a hardcoded alpha (1.0).
    """
    r = rng.random()
    g = rng.random()
    b = rng.random()

    col = Color(r, g, b, 1.0)

    # Sometimes both stroke and fill, sometimes only one
    if stroke_only:
        canvas.do.stroke_color(col)
    else:
        if rng.random() < 0.5:
            canvas.do.stroke_color(col)
        if rng.random() < 0.9:
            canvas.do.fill_color(col)


# Example integration with your existing mutator:
#
# def mutate_pdf_inplace(pdf: Pdf, rng: Optional[random.Random] = None) -> None:
#     if rng is None:
#         rng = random.Random()
#
#     # 1. Existing property-level mutators (forms, attachments, etc.)
#     mutate_forms(pdf, rng=rng)
#     mutate_attachments(pdf, rng=rng)
#     # ...other structural/property mutations...
#
#     # 2. Overlay random canvas drawing on each page
#     overlay_random_canvas(pdf, max_operations=1000, rng=rng)


def rand_choice(rng: random.Random, seq):
    if not seq:
        return None
    return seq[rng.randrange(len(seq))]


def mutate_docinfo(pdf: Pdf, rng: random.Random) -> None:
    """Mutate the old-school document info dictionary."""
    info = pdf.docinfo  # ensures dictionary exists
    # Change some common fields
    info[Name.Title] = rng.choice(HARD_CODED_STRINGS)
    info[Name.Author] = rng.choice(HARD_CODED_STRINGS)
    info[Name.Subject] = "mutated-subject-" + str(rng.randrange(1_000_000))
    info[Name.Creator] = "pikepdf-mutator"
    info[Name.Producer] = "pikepdf-mutator-libqpdf"

    # Add some weird custom keys
    info[Name("/FuzzKey")] = rng.choice(HARD_CODED_STRINGS)
    info[Name("/VeryLongKey" + "X" * 30)] = "V" * 200


def mutate_metadata(pdf: Pdf, rng: random.Random) -> None:
    """Mutate XMP metadata in a safe way using open_metadata()."""
    try:
        with pdf.open_metadata() as meta:
            meta["dc:title"] = rng.choice(HARD_CODED_STRINGS)
            meta["dc:creator"] = [rng.choice(HARD_CODED_STRINGS)]
            meta["pdf:Keywords"] = "fuzz,mutated,property"
            meta["xmp:ModifyDate"] = datetime.datetime.utcnow().isoformat() + "Z"
    except Exception:
        # Some PDFs have totally broken XMP; just ignore failures
        pass


def mutate_pages(pdf: Pdf, rng: random.Random) -> None:
    """Mutate page-level properties such as MediaBox, Rotate and Resources."""
    for page in pdf.pages:
        # Randomly rotate page
        if rng.random() < 0.5:
            page.Rotate = rng.choice([0, 90, 180, 270])

        # Slightly tweak mediabox width/height using Decimal-safe operations
        mb = page.MediaBox
        if len(mb) == 4:
            # Scale width / height by a small factor
            for idx in (2, 3):
                try:
                    mb[idx] = mb[idx] * (1 + (rng.random() - 0.5) * 0.2)
                except Exception:
                    pass

        # Corrupt /Resources a bit but still keep it a dictionary
        if rng.random() < 0.3:
            res = page.get("/Resources", None)
            if isinstance(res, Dictionary):
                # Add a bogus font or xobject entry
                res[Name("/FuzzRes" + str(rng.randrange(100)))] = pdf.make_indirect(
                    Dictionary(Fuzz="Yes", Time=str(datetime.datetime.utcnow()))
                )

def mutate_da_string(da_bytes, rng):
    """
    Mutate a /DA string using VALID PDF text-drawing operators.
    Produces weird but still legal appearance instructions.
    """
    dprint("Doing the thing...")
    # Convert to text safely
    try:
        da = da_bytes.decode("latin1")
    except Exception:
        da = "/Helv 12 Tf 0 g"

    # Possible valid drawing fragments
    parts = []

    for _ in range(rng.randrange(MAX_DA_MUTATION_STEPS)):

        if rng.random() < 0.7:
            parts.append(f"/Helv {rng.randint(1, 10000)} Tf")        # random font size
        if rng.random() < 0.7:
            parts.append(f"{rng.uniform(0,1):.3f} g")             # non-stroke color
        if rng.random() < 0.7:
            parts.append(f"{rng.uniform(0,1):.3f} G")             # stroke color
        if rng.random() < 0.5:
            parts.append(f"{rng.randint(-10000 ,10000)} Tc")             # char spacing
        if rng.random() < 0.5:
            parts.append(f"{rng.randint(-10000,10000)} Tw")             # word spacing
        if rng.random() < 0.3:
            # random text matrix (valid)
            a = rng.uniform(0.5, 2)
            d = rng.uniform(0.5, 2)
            e = rng.randint(-10000, 10000)
            f = rng.randint(-10000, 10000)
            parts.append(f"{a} 0 0 {d} {e} {f} Tm")

    # Join into a valid DA string
    mutated = " ".join(parts)
    dprint("Here is the mutated DA string: "+str(mutated))
    if not mutated:
        mutated = "/Helv 12 Tf 0 g"

    return mutated.encode("latin1")

def mutate_acroform(pdf: Pdf, rng: random.Random) -> None:
    """Mutate interactive form fields using both low-level AcroForm + high-level Form."""
    if not hasattr(pdf, "acroform"):
        return
    acro = pdf.acroform
    if not acro.exists:
        return

    # Toggle NeedAppearances flag
    acro.needs_appearances = not acro.needs_appearances

    # Mutate inherited default appearance stream
    if rng.random() < 0.4:
        # da = acro.object.get("/DA", b"/Helv 12 Tf 0 g")
        # acro.object["/DA"] = da + b" % fuzzy"

        acro = pdf.acroform
        acro_dict = pdf.Root.get("/AcroForm", None)   # raw dictionary

        if isinstance(acro_dict, Dictionary):
            if "/DA" not in acro_dict: # Check the stuff...
                dprint("DA not found here: "+str(acro_dict))
                exit(1)
            da = acro_dict.get("/DA", b"/Helv 12 Tf 0 g")
            # Replace with valid drawing-like DA (see fix #3)
            acro_dict["/DA"] = mutate_da_string(da, rng)
            pdf.generate_appearance_streams()
            dprint("Here is the final /DA stuff: "+str(acro_dict["/DA"]))
            
            try:
                for fdict in acro.fields:
                    ap = fdict.obj.get("/AP", None)
                    if isinstance(ap, Dictionary):
                        # Delete normal appearance
                        if "/N" in ap:
                            del ap["/N"]
            except Exception:
                pass

            return # Return here...


    # Mutate fields using the higher-level Form wrapper
    form = Form(pdf)
    for name, field in form.items():
        # Hard-coded mutations by type
        # Checkbox
        if field.__class__.__name__.endswith("CheckboxField"):
            if rng.random() < 0.7:
                field.checked = not field.checked
        # Choice/Combobox
        if field.__class__.__name__.endswith("ChoiceField"):
            '''
            if field.options:
                opt = rand_choice(rng, field.options)
                if hasattr(opt, "display_value"):
                    try:
                        field.value = opt.display_value
                    except ValueError:
                        pass
            '''

            opts = list(field.options)

            # Editable combobox → allow any value
            if field.is_combobox and field.allow_edit:
                # field.value = rng.choice(HARD_CODED_STRINGS)
                field.value = mutate_string(str(field.value), rng) # Mutate the string
                continue

            # Otherwise MUST pick one of the preset options
            if opts:
                try:
                    sel = rng.choice(opts)
                    field.value = sel.display_value
                except Exception:
                    pass
            continue

        elif isinstance(field, type(form["Text1"]) if "Text1" in form else type(field)):
            # TextField-ish
            dprint("Mutating this here: "+str(field))
            if rng.random() < 0.7:
                # field.value = rng.choice(HARD_CODED_STRINGS)
                field.value = mutate_string(str(field.value), rng)

    # Mutate low-level field dictionaries a bit
    for fobj in acro.fields:
        # Add a custom key to the field dictionary directly
        try:
            fobj.obj["/FuzzFlag"] = rng.randrange(0, 2**16)
        except Exception:
            pass


def mutate_annotations(pdf: Pdf, rng: random.Random) -> None:
    """Mutate annotation properties: flags, appearance states, contents."""
    for page in pdf.pages:
        annots = getattr(page, "Annots", None)
        if not annots:
            continue
        for annot in annots:
            # Mutate flags (bitfield)
            if hasattr(annot, "F"):
                try:
                    annot.F = (int(annot.F) ^ rng.randrange(0, 0xFF)) & 0xFFFF
                except Exception:
                    pass

            # Mutate Contents if it's a text annotation / widget
            if "/Contents" in annot:
                annot["/Contents"] = rng.choice(HARD_CODED_STRINGS)

            # If annotation has an appearance dict, flip AS (appearance state)
            ap = annot.get("/AP", None)
            if isinstance(ap, Dictionary):
                normal = ap.get("/N", None)
                if isinstance(normal, Dictionary) and normal.keys():
                    # Pick some random state name
                    state_name = rand_choice(rng, list(normal.keys()))
                    annot["/AS"] = state_name


def mutate_attachments(pdf: Pdf, rng: random.Random) -> None:
    """Mutate embedded file specifications via Attachments mapping + AttachedFileSpec."""
    attachments = pdf.attachments

    # Randomly delete some attachments
    for key in list(attachments.keys()):
        if rng.random() < 0.3:
            try:
                del attachments[key]
            except Exception:
                pass

    # Randomly add one attachment with some fuzz data
    if rng.random() < 0.7:
        data = rng.choice(HARD_CODED_STRINGS).encode("utf-8")
        fs = AttachedFileSpec(
            pdf,
            data,
            description="fuzz-attachment",
            relationship=Name.Data,
        )
        fs.filename = f"fuzz-{rng.randrange(100000)}.txt"
        attachments[fs.filename] = fs

    # Mutate metadata of existing attachments
    for name, fs in list(attachments.items()):
        try:
            fs.description = rng.choice(HARD_CODED_STRINGS)
            attached = fs.get_file()
            attached.mime_type = "application/x-fuzz"
            attached.mod_date = datetime.datetime.utcnow()
        except Exception:
            pass


def mutate_images(pdf: Pdf, rng: random.Random) -> None:
    """
    Mutate image *properties* via PdfImage, but do NOT touch raw image bytes.
    We tweak: ColorSpace, BitsPerComponent, Decode, DecodeParms, filters, etc.
    """
    for page in pdf.pages:
        images = getattr(page, "images", {})
        for name, xobj in images.items():
            try:
                pim = PdfImage(xobj)
            except Exception:
                continue

            # Mutate BitsPerComponent in dictionary (may confuse decoders)
            if rng.random() < 0.4 and "BitsPerComponent" in xobj.stream_dict:
                bpc = xobj.stream_dict["/BitsPerComponent"]
                # Flip between some plausible values
                new_bpc = rng.choice([1, 2, 4, 8, 16])
                xobj.stream_dict["/BitsPerComponent"] = new_bpc

            # Mutate Decode array
            if rng.random() < 0.4:
                comps = {
                    "RGB": 3,
                    "CMYK": 4,
                    "L": 1,
                    "1": 1,
                }.get(pim.mode, 1)
                dec = []
                for _ in range(comps):
                    lo = 0.0 if rng.random() < 0.5 else 1.0
                    hi = 1.0 if lo == 0.0 else 0.0
                    dec.extend([lo, hi])
                xobj.stream_dict["/Decode"] = dec

            # Flip BlackIs1 flag for CCITT-like images
            dp = xobj.stream_dict.get("/DecodeParms", None)
            if isinstance(dp, Dictionary) and rng.random() < 0.5:
                dp["/BlackIs1"] = not bool(dp.get("/BlackIs1", False))

            # Mutate ColorSpace to something compatible-but-weird
            cs = xobj.stream_dict.get("/ColorSpace", None)
            if cs == Name.DeviceGray and rng.random() < 0.3:
                xobj.stream_dict["/ColorSpace"] = Name.DeviceRGB
            elif cs == Name.DeviceRGB and rng.random() < 0.3:
                xobj.stream_dict["/ColorSpace"] = Name.DeviceGray

            # Optionally wrap ColorSpace in an Indexed colorspace with a fake palette
            if rng.random() < 0.2 and not pim.indexed:
                base_cs = xobj.stream_dict.get("/ColorSpace", Name.DeviceRGB)
                hival = 3
                palette = b"\x00\x00\x00\xff\x00\x00\x00\xff\x00\x00\x00\xff"
                xobj.stream_dict["/ColorSpace"] = Array(
                    [Name.Indexed, base_cs, hival, palette]
                )


def mutate_trailer(pdf: Pdf, rng: random.Random) -> None:
    """Mutate some keys in the trailer dictionary (indirectly via pdf.trailer)."""
    try:
        tr = pdf.trailer
        tr[Name("/FuzzTrailerKey")] = rng.choice(HARD_CODED_STRINGS)
        # Randomize /Info ref if present (still an Object)
        if "/Info" in tr:
            tr["/Info"] = pdf.docinfo  # ensure it's a valid dictionary object
    except Exception:
        pass


def mutate_pdf_in_memory(data: bytes, seed: int | None = None) -> bytes:
    """
    In-memory variant: open PDF from bytes, mutate, and return bytes.
    Good for plugging into AFL++ custom mutator / honggfuzz / etc.
    """

    global not_reached

    rng = random.Random(seed)
    bio = io.BytesIO(data)

    try:
        with Pdf.open(bio, allow_overwriting_input=False) as pdf:
            
            mutate_docinfo(pdf, rng)
            mutate_metadata(pdf, rng)
            mutate_pages(pdf, rng)
            
            mutate_acroform(pdf, rng)
            
            mutate_annotations(pdf, rng)
            mutate_attachments(pdf, rng)
            mutate_images(pdf, rng)
            mutate_trailer(pdf, rng)
            
            if rng.random() < 0.3: # Add a random image thing...
                dprint("Inserting a random image...")
                insert_random_colorspace_image(pdf, rng=rng)
            pdf.remove_unreferenced_resources()
            # Do the stuff...
            overlay_random_canvas(pdf, max_operations=MAX_DRAW_OPERATIONS, rng=rng)
            out = io.BytesIO()
            pdf.save(out, static_id=False, deterministic_id=False)
            return bytes(out.getvalue())
    except Exception as exception:
        if DEBUG: # Print fatal exceptions in debugging.
            dprint("We got this bullshit ass exception here: "+str(exception))
            dprint(traceback.print_exception(type(exception), exception, exception.__traceback__))
            exit(1)
        return data
        # dprint("Poopoooo...")
        # dprint("Exception here: "+str(exception))
        # dprint(traceback.print_exception(type(exception), exception, exception.__traceback__))
        # exit(1)

'''
def mutate_pdf_file(
    in_path: str | Path, out_path: str | Path, seed: int | None = None
) -> None:
    """
    File-based entry point. Reads input PDF, mutates, writes out_path.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    data = in_path.read_bytes()
    mutated = mutate_pdf_in_memory(data, seed=seed)
    out_path.write_bytes(mutated)
'''


# -----------------------------
# Utilities: convert pikepdf objects -> python-serializable repr and back
# -----------------------------
def pike_to_py(obj: Any, depth: int = 0) -> Dict[str, Any]:
    """
    Convert pikepdf object to a Python-serializable structure.
    Supported: Name, Dictionary, Array, Stream (represented as dict), numbers, bool, bytes/str.
    """
    global _call_counter
    _call_counter += 1
    if _call_counter > MAX_CALL_COUNT:
        raise RuntimeError("conversion call limit exceeded")

    if isinstance(obj, Name):
        return {"__type__": "name", "value": str(obj)}  # e.g. "/F1"

    if isinstance(obj, Stream):
        d = {}
        try:
            for k, v in obj.items():
                # avoid deep recursion
                if depth >= MAX_RECURSION:
                    d[str(k)] = {"__type__": "unknown"}
                else:
                    d[str(k)] = pike_to_py(v, depth=depth+1)
        except Exception:
            pass
        # attempt to read bytes
        try:
            raw = obj.read_bytes() or b""
        except Exception:
            raw = b""
        return {"__type__": "stream", "dict": d, "stream_bytes": bytes(raw)}

    if isinstance(obj, Dictionary):
        out = {}
        if depth >= MAX_RECURSION:
            return {"__type__": "dict", "value": out}
        for k, v in obj.items():
            try:
                out[str(k)] = pike_to_py(v, depth=depth+1)
            except Exception as e:
                raise(e)
                out[str(k)] = {"__type__": "unknown"}
        return {"__type__": "dict", "value": out}

    if isinstance(obj, Array):
        lst = []
        for v in obj:
            try:
                lst.append(pike_to_py(v, depth=depth+1))
            except Exception as e:
                raise(e)
                lst.append({"__type__": "unknown"})
        return {"__type__": "array", "value": lst}

    if isinstance(obj, (int, float, bool, decimal.Decimal)): # Also check for decimal stuff...
        return {"__type__": "primitive", "value": obj}

    if isinstance(obj, bytes):
        return {"__type__": "bytes", "value": obj}

    if isinstance(obj, str):
        return {"__type__": "string", "value": obj}
    assert False
    # print("This here is unknown stuff: "+str(obj))
    # print("type of the thing: "+str(type(obj)))
    # return {"__type__": "unknown", "repr": str(obj)}


def py_to_pike(pyobj: Any, pdf: pikepdf.Pdf = None) -> Any:
    """
    Convert Python-serializable representation back to pikepdf objects.
    Returns pikepdf object (Name/Dictionary/Array/Stream/primitive) or special marker for stream construction.
    """
    if not isinstance(pyobj, dict) or "__type__" not in pyobj:
        # allow raw primitives
        if isinstance(pyobj, (int, float, bool)):
            return pyobj
        if isinstance(pyobj, bytes):
            return pyobj
        if isinstance(pyobj, str):
            return pyobj
        raise ValueError("pyobj missing type: %r" % (pyobj,))

    t = pyobj["__type__"]

    if t in ("name"):
        v = pyobj.get("value", "")
        if not isinstance(v, str):
            v = str(v)
        if not v.startswith("/"):
            v = "/" + v
        # if len(v) == 1:
        #     v = v + "A"
        return Name(v)

    if t == "primitive":
        return pyobj.get("value")

    if t == "bytes":
        return pyobj.get("value", b"")

    if t == "string":
        return pyobj.get("value", "")

    if t == "array":
        out = Array()
        for el in pyobj.get("value", []):
            out.append(py_to_pike(el, pdf=pdf))
        return out

    if t == "dict":
        d = pyobj.get("value", {})
        out = Dictionary()
        for k_str, v_py in d.items():
            if k_str.startswith("/"):
                key_name = k_str
            else:
                key_name = "/" + k_str
            k = Name(key_name)
            out[k] = py_to_pike(v_py, pdf=pdf)
        return out

    if t == "stream":
        metadata = pyobj.get("dict", {})
        stream_bytes = pyobj.get("stream_bytes", b"")
        md = Dictionary()
        for k_str, v_py in metadata.items():
            key_name = k_str if k_str.startswith("/") else "/" + k_str
            md[Name(key_name)] = py_to_pike(v_py, pdf=pdf)
        # pikepdf requires a Pdf owner to create Stream objects cleanly.
        # If we can't create a pike Stream (pdf is None) we return a special marker for caller to construct.
        if pdf is None:
            return {"__construct_stream__": {"dict": md, "bytes": stream_bytes}}
        s = pikepdf.Stream(pdf, stream_bytes)
        for kk, vv in md.items():
            kk_str = str(kk)
            if kk_str in BANNED_KEYS:
                continue
            s[kk] = vv
        return s

    raise ValueError("Unsupported py -> pike type: " + t)

def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Extract arbitrary objects from a PDF file.
    Not limited to resources; captures any Dictionary, Array, or Stream.
    """
    samples = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            # always try page resources first (still useful)
            for p in pdf.pages:
                try:
                    r = p.get("/Resources")
                    if r:
                        samples.append(pike_to_py(r))
                except Exception:
                    pass

            # now grab arbitrary objects
            for obj in pdf.objects:
                try:
                    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Array, pikepdf.Stream)):
                        the_thing = pike_to_py(obj)
                        # Check if the thing is an empty result, if yes, then do not add it...
                        if the_thing["__type__"] == "stream": # Check stream
                            # dprint("the thing: "+str(the_thing))
                            # dprint("length of the bullshit: "+str(len(the_thing["stream_bytes"])))
                            if len(the_thing["stream_bytes"]) == 0: # Check empty stuff...
                                continue # Continue if we have the shit...
                        samples.append(the_thing)
                except Exception:
                    continue
    except Exception as e:
        print(f"Warning: failed to open {pdf_path}: {e}", file=sys.stderr)
    return samples

# def obj_to_dict(obj) -> dict: # Convert object to dictionary...


def is_critical_object(obj, pdf) -> bool:
    try:
        # Catalog (Root is the Catalog in PDFs)
        if "/Type" in obj and str(obj["/Type"]) == "/Catalog":
            return True
        if "/Type" in obj and str(obj["/Type"]) == "/Pages":
            # print("stuff")
            # print(obj)
            # print(obj["/Kids"])
            return True
        if "/Kids" in obj:
            return True
        # Root dictionary
        if obj == pdf.root:
            return True
        # Pages dictionary
        if "/Pages" in pdf.root and obj == pdf.root["/Pages"]:
            return True
    except Exception:
        return False
    return False

def build_resources_db_from_dir(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    print(pdf_dir)
    db: List[Dict[str, Any]] = []
    if not pdf_dir.exists() or not pdf_dir.is_dir():
        print(f"PDF dir {pdf_dir} not found; returning empty DB", file=sys.stderr)
        return db

    for p in sorted(pdf_dir.iterdir()):
        if not p.is_file() or p.suffix.lower() != ".pdf":
            continue
        try:
            print(p.name)
            samples = extract_resource_samples_from_pdf(p)
            if samples:
                db.extend(samples)
            if len(db) >= MAX_DB_SIZE:
                break
        except Exception:
            pass

    try:
        with open(pkl_path, "wb") as fh:
            pickle.dump(db[:MAX_DB_SIZE], fh)
    except Exception as e:
        print(f"Warning: could not write resources pkl {pkl_path}: {e}", file=sys.stderr)
    return db[:MAX_DB_SIZE]


def load_resources_db(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    # prefer pickle if present and up-to-date relative to pdf_dir
    if pkl_path.exists():
        try:
            pkl_mtime = pkl_path.stat().st_mtime
            rebuild = False
            if pdf_dir.exists() and pdf_dir.is_dir():
                for p in pdf_dir.iterdir():
                    if p.suffix.lower() == ".pdf" and p.stat().st_mtime > pkl_mtime:
                        rebuild = True
                        break
            if not rebuild:
                with open(pkl_path, "rb") as fh:
                    db = pickle.load(fh)
                    if isinstance(db, list):
                        return db
        except Exception:
            pass
    dlog("PDF_DIR: "+str(pdf_dir))
    return build_resources_db_from_dir(pdf_dir, pkl_path)


# -----------------------------
# Deterministic RNG from input buffer
# -----------------------------
def rng_from_buf(buf: bytes) -> random.Random:
    """
    Create a deterministic RNG seeded from the input buffer bytes (excluding header).
    Use a stable hash of a slice to seed the RNG.
    """
    # raw = buf[HEADER_SIZE:HEADER_SIZE + 128]
    # if not raw:
    #     raw = buf[:HEADER_SIZE] or b"\x00"
    # h = hashlib.sha256(raw).digest()
    # seed_int = int.from_bytes(h[:8], "little")
    # seed_thing = random.randrange(1,1000)
    # print("seed: "+str(seed_thing))
    # rand_thing = random.randrange(1, 1000000000000)
    # dprint("We chose this random thing here: "+str(rand_thing))
    # rand_thing = 525584941424 # Hardcoded bullshit here...
    rand_thing = random.randrange(100000000)
    return random.Random(rand_thing) # random.Random(random.randrange(1,10000000)) # random.Random(len(buf)) # random.Random(seed_int) # random.Random(seed_thing) # random.Random(random.randrange(1000000)) # random.Random(seed_int)


# -----------------------------
# Mutation helpers (deterministic with provided rng)
# -----------------------------
def pick_choice(seq, rng: random.Random):
    if not seq:
        return None
    return seq[rng.randrange(len(seq))]

def collect_named_objects(pdf) -> List[Name]:
    """
    Collect all Name keys that look like indirect references or valid names
    inside the current PDF. Used to generate replacements instead of nonsense.
    """
    names = []
    try:
        for obj in pdf.objects:
            if isinstance(obj, Dictionary):
                for k, v in obj.items():
                    if isinstance(v, Name):
                        names.append(v)
            elif isinstance(obj, Array):
                for v in obj:
                    if isinstance(v, Name):
                        names.append(v)
    except Exception:
        pass
    # fallback if nothing found
    if not names:
        names = [Name("/Fallback")]
    return names

def mut_string(string: str, rng: random.Random) -> str:
    global not_reached
    if string == "": # Check for empty strings before trying to mutate the object...
        string = "samplestringhere....erereree"
    dprint("Called mut_string with this string here: "+str(string))
    rand_mult = random.randrange(1, MAX_STRING_MULT_COUNT)
    dprint("rand_mult: "+str(rand_mult))
    dprint("MAX_STRING_SIZE//len(string): "+str(MAX_STRING_SIZE//len(string)))
    
    intermediate = mutate_string_generic(string, rng)

    res = intermediate * min(rand_mult, MAX_STRING_SIZE//len(intermediate))
    # assert len(res) <= MAX_STRING_SIZE # Should be the maximum size thing...
    if not len(res) <= MAX_STRING_SIZE:
        print("poopooo"*1000)
        exit(1)
    dprint("result: "+str(res))
    return res

def mutate_string_generic(string: str, rng: random.Random) -> str: # Generic string mutation function...
    if rng.random() < 0.95:  # mostly mutate existing string
        if len(string) > 1:
            s = string
            action = rng.choice(["dup", "remove", "flip"])
            if action == "dup":
                start = rng.randrange(len(s))
                if start+1 == len(s):
                    # Avoid empty ranges.
                    end = 1_000_000_000
                else:
                    end = rng.randrange(start+1, len(s))
                piece = s[start:end]
                insert_at = rng.randrange(len(s))
                dprint("Doing the string stuff...")
                return s[:insert_at] + piece * rng.randrange(MAX_STRING_MULT_COUNT) + s[insert_at:]
            elif action == "remove":
                start = rng.randrange(len(s))
                end = rng.randrange(start, len(s))
                return s[:start] + s[end:]
            elif action == "flip":
                idx = rng.randrange(len(s))
                return s[:idx] + chr(rng.randrange(32, 127)) + s[idx+1:]
        else:
            return string + "X"
    else:  # generate new
        s = "".join(chr(32 + rng.randrange(95)) for _ in range(rng.randint(1, MAX_STRING_SIZE)))
        return s
    assert False
    # return new_str

# ————————————————————————————————
# Helpers: specific mutations
# ————————————————————————————————

def mutate_int(val, rng):
    return val + rng.randint(-MAX_INTEGER_RANGE, MAX_INTEGER_RANGE)


def mutate_number(val, rng):
    factor = 1.0 + (rng.random() - 0.5) * MAX_SCALE_FACTOR
    return float(val) * factor


def mutate_string(val, rng):
    return mut_string(str(val), rng)


def mutate_name(val, rng, pdf):
    if pdf:
        names = collect_named_objects(pdf)
        if names:
            return rng.choice(names)
    return Name("/Alt" + str(rng.randint(0, 99999)))


def mutate_bool(val):
    return not bool(val)


def mutate_dict(val, rng, depth, pdf):
    if depth < MAX_RECURSION:
        mutate_dict_inplace(val, rng, depth + 1, pdf)
    return val


def mutate_stream(val, rng, pdf):
    mutate_stream_inplace(val, rng, pdf)
    return val


# ————————————————————————————————
# Arrays are complex — extract cleanly
# ————————————————————————————————

def mutate_array(arr: Array, rng, pdf):
    # empty → append new int
    global not_reached
    if len(arr) == 0:
        arr.append(rng.randint(-100, 100))
        return arr

    # action = rng.choice(["mutate_elem", "duplicate", "remove", "append"])

    action = rng.choice(["mutate_elem", "remove", "append"])

    if action == "mutate_elem":
        assert isinstance(arr, Array) # Actually should be an array...
        # arr = arr.as_list()
        idx = rng.randrange(len(arr))
        elem = arr[idx]

        if isinstance(elem, int):
            dprint("Ok, so now we are doing the thing here... Here is the object: "+str(arr))
            arr[idx] = clamp_int_32(random.randrange(-MAX_32_INT, MAX_32_INT)) # random.randrange(1000) # Just put an integer there...
            dprint("After: "+str(arr))
            # not_reached = False
            return arr
        elif isinstance(elem, float):
            arr[idx] = elem * (rng.random() - 0.5) * MAX_SCALE_FACTOR

        elif isinstance(elem, str):
            s = elem
            if len(s) > 1:
                start = rng.randrange(len(s))
                end = rng.randrange(start, len(s))
                arr[idx] = s[:start] + s[end:]
            else:
                arr[idx] = elem + "X"

        elif isinstance(elem, Name):
            if pdf:
                names = collect_named_objects(pdf)
                if names:
                    arr[idx] = rng.choice(names)
        elif isinstance(elem, Dictionary):
            # not_reached = False
            dprint("Mutating this here: "+str(elem))
            # mutate_dict(elem) # Mutate the dictionary...
            mutate_dict(elem, rng, 0, pdf) # ;)
            dprint("After mutation: "+str(elem))
        elif isinstance(elem, pikepdf.Stream): # Mutate stream...
            mutate_stream_inplace(elem, rng, pdf)
        elif isinstance(elem, str): # Is a string???
            mutate_string(elem)
            not_reached = False
        elif isinstance(elem, float) or isinstance(elem, decimal.Decimal):
            # Float???
            elem = mutate_number(elem, rng)
        elif isinstance(elem, Array): # Recurse here...
            elem = mutate_array(elem, rng, pdf)
        elif isinstance(elem, Name): # Name
            elem = mutate_name(elem, rng, pdf) # Just mutate that name shit...
        else:
            dprint("Unsupported target: "+str(elem))
            dprint("Type: "+str(type(elem)))
            dprint("repr: "+str(repr(elem)))
            exit(1)
        # Add support for strings here...


    elif action == "duplicate":
        src = rng.randrange(len(arr))
        tgt = rng.randrange(len(arr))
        dprint("Passed this object here: "+str(arr))
        dprint("arr")
        # global not_reached
        arr[tgt] = arr[src]

    elif action == "remove" and len(arr) > 1:
        dprint("arr: "+str(arr))
        del arr[rng.randrange(len(arr))]

    elif action == "append":
        arr.append(rng.choice(arr))

    # Large-scale duplication
    if rng.random() < 0.10 and arr:
        copies = rng.randrange(2, 20)
        new_list = []
        for _ in range(copies):
            new_list.extend(arr)
        return Array(new_list)

    # Explode size
    if rng.random() < 0.10:
        grow = rng.randrange(200, 20000)
        for _ in range(grow):
            arr.append(rng.choice(arr))

            # arr.append(copy.deepcopy(rng.choice(arr)))

    # Shrink
    # if rng.random() < 0.10 and len(arr) > 1:
    #     del arr[0:len(arr)//2]

    '''
    if rng.random() < 0.10 and len(arr) > 1:
        dprint("Array: "+str(arr))
        dprint("Array thing: "+str(arr.__dir__()))
        arr = arr.as_list()
        arr.pop(rng.randrange(len(arr)))
    '''

    return arr


# ————————————————————————————————
# Generic inferred mutation path
# Mirrors your explicit logic exactly
# ————————————————————————————————

BANNED_THINGS = [Array, Name]

def mutate_inferred(obj, key, val, rng, depth, pdf):
    """Fallback mutation when we don't have an expected type in DICT_TYPE_MAP."""

    dprint("Called mutate_inferred with obj == " + str(obj))
    dprint("Here is the value: " + repr(val))

    # 95% chance: mutate according to inferred type
    if rng.random() < 0.95:

        # ---- Integers / booleans ----
        # pikepdf often wraps numbers, but int() / float() will work if they are numeric.
        try:
            if isinstance(val, int):
                obj[key] = mutate_int(int(val), rng)
                return
        except Exception:
            pass

        try:
            if isinstance(val, bool):
                obj[key] = mutate_bool(val)
                return
        except Exception:
            pass

        # ---- Floats / reals ----
        try:
            # we check float conversion in a guarded way
            if not isinstance(val, int):  # avoid treating ints as float here
                f = float(val)
                obj[key] = mutate_number(f, rng)
                return
        except Exception:
            pass

        # ---- Names ----
        if isinstance(val, Name):
            obj[key] = mutate_name(val, rng, pdf)
            return

        # ---- Arrays ----
        if isinstance(val, Array):
            obj[key] = mutate_array(val, rng, pdf)
            dprint("After thing: "+str(obj[key]))
            return

        # ---- Dictionaries ----
        if isinstance(val, Dictionary):
            mutate_dict(val, rng, depth, pdf)
            obj[key] = val
            return

        # ---- Streams ----
        if isinstance(val, Stream):
            obj[key] = mutate_stream(val, rng, pdf)
            return

        # ---- "Everything else" → treat as string-like ----
        # Includes things like pikepdf.Object that represent strings or DA-like content.
        try:
            s = str(val)
        except Exception:
            s = repr(val)

        dprint("Treating value as string for mutation: " + s)
        obj[key] = mutate_string(s, rng)
        dprint("New value is " + str(obj[key]))
        return

    # 5%: insert wrong-type garbage on purpose
    obj[key] = rng.randint(-5000, 5000)


# ————————————————————————————————
# Dispatch table for expected types
# ————————————————————————————————

EXPECTED_TYPE_HANDLERS = {
    "int":          lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_int(val, rng)),
    "number":       lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_number(val, rng)),
    "array":        lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_array(val, rng, pdf)),
    "name":         lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_name(val, rng, pdf)),
    "bool":         lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_bool(val)),
    "string":       lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_string(val, rng)),
    "dict":         lambda obj, key, val, rng, depth, pdf: mutate_dict(val, rng, depth, pdf),
    "stream":       lambda obj, key, val, rng, depth, pdf: obj.__setitem__(key, mutate_stream(val, rng, pdf))
}


# ————————————————————————————————
# MAIN MUTATOR
# ————————————————————————————————

def mutate_dict_inplace(obj: Dictionary, rng: random.Random, depth: int = 0, pdf=None):
    if not isinstance(obj, Dictionary) or not obj.keys():
        return False

    key = pick_choice(list(obj.keys()), rng)
    if key is None:
        return False

    expected_type = DICT_TYPE_MAP.get(str(key).lstrip("/"), "any")
    val = obj[key]

    try:
        # If expected type is known & matches → use direct handler
        if expected_type in EXPECTED_TYPE_HANDLERS:
            dprint("Here we are looking up the thing: "+str(expected_type))
            dprint("We are doing it with this key here: "+str(key))
            dprint("Here is the actual thing: "+str(val))
            EXPECTED_TYPE_HANDLERS[expected_type](obj, key, val, rng, depth, pdf)
            dprint("Value after the thing: "+str(val))
        else:
            # Otherwise: use inferred type-based mutation
            mutate_inferred(obj, key, val, rng, depth, pdf)

    except Exception as exception:

        dprint("Exception during mutation of dictionary: "+str(exception))
        dprint(traceback.print_exception(type(exception), exception, exception.__traceback__))
        exit(1)
        # You can choose to swallow or rethrow
        # raise e

    return True

def is_drawing_stream(stream: Stream) -> bool:
    try:
        # Page contents often lack obvious markers so use heuristics
        # parent = stream.get_parent()
        # if isinstance(parent, Dictionary) and parent.get("/Type") == "/Page":
        #     return True

        # streams with these keys are *not* content streams
        for bad in ("/Subtype", "/Width", "/Height", "/Filter"):
            if bad in stream:
                return False

        # simple heuristic: content streams often contain operator keywords
        sample = stream.read_bytes()[:2000]
        markers = [b"m", b"l", b"re", b"Tf", b"BT", b"ET", b"cm", b"Do", b"rg", b"RG"]
        return any(m in sample for m in markers)

    except Exception as e:
        dprint("Exception when checking if drawing stream: "+str(e))
        exit(1)
        return False

def tokenize_content_stream(data: bytes):
    """
    Tokenize operands + operators from a content stream.
    Returns a list of (operands, operator) entries.
    Example:
        b"10 20 m 30 40 l S" →
        [
            (["10", "20"], "m"),
            (["30", "40"], "l"),
            ([], "S")
        ]
    """
    import re

    toks = re.findall(rb"/?[A-Za-z0-9\.\-\+]+|\[|\]|<<|>>", data)
    ops = []
    operands = []

    # PDF operators are alphabetic (e.g., m, l, re, Tf, BT, ET)
    def is_operator(tok):
        return tok.isalpha() or all(chr(c).isalpha() for c in tok)

    for t in toks:
        if is_operator(t):
            ops.append((operands.copy(), t.decode("latin1")))
            operands = []
        else:
            operands.append(t.decode("latin1"))

    return ops

PDF_COLOR_OPS = ["rg", "RG", "k", "K", "g", "G", "cs", "CS", "sc", "SC"]
PDF_TEXT_OPS = ["Tf", "Tj", "TJ", "BT", "ET", "Td", "TD", "Tm"]
PDF_MATRIX_OPS = ["cm", "Tm"]
PDF_PATH_OPS = ["m", "l", "c", "h", "re"]
PDF_CLIP_OPS = ["W", "W*"]
PDF_XOBJECT_OPS = ["Do"]

UNKNOWN_OPS = ["ZZ", "qq", "WTF", "noop", "hack", "xxx", "BAD"]


def mutate_operator_list(ops, rng, pdf):
    if not ops:
        return ops


    # global not_reached
    # not_reached = False
    # names = collect_named_objects(pdf)

    choice = rng.randrange(12)   # increased number of mutation types

    # ---------------------------------------------------------------
    # 0. Mutate numeric operands aggressively
    # ---------------------------------------------------------------
    if choice == 0:
        entry = rng.choice(ops)
        operands, op = entry
        for i, tok in enumerate(operands):
            try:
                val = float(tok)
                # mutate numeric values heavily
                val = val * (1.0 + (rng.random() - 0.5) * 10.0)
                # occasional extreme values
                if rng.random() < 0.1:
                    val = rng.uniform(-1e6, 1e6)
                operands[i] = str(val)
            except:
                pass
        return ops


    # ---------------------------------------------------------------
    # 1. Mutate operator (replace with random one)
    # ---------------------------------------------------------------
    if choice == 1:
        entry = rng.choice(ops)
        entry[1] = rng.choice(PDF_DRAWING_OPS + UNKNOWN_OPS)
        return ops


    # ---------------------------------------------------------------
    # 2. Insert new operator (structured)
    # ---------------------------------------------------------------
    if choice == 2:
        idx = rng.randrange(len(ops))
        new_op = rng.choice(PDF_DRAWING_OPS + PDF_COLOR_OPS +
                            PDF_TEXT_OPS + PDF_CLIP_OPS + UNKNOWN_OPS)
        operands = []

        # numeric operand operators
        if new_op in ["m", "l", "Td", "TD"]:
            operands = [str(rng.uniform(-500, 500)),
                        str(rng.uniform(-500, 500))]

        elif new_op in ["c"]:  # curve takes 6 operands
            operands = [str(rng.uniform(-500, 500)) for _ in range(6)]

        elif new_op in ["re"]: # rectangle
            operands = [str(rng.uniform(-200, 200)) for _ in range(4)]

        elif new_op in PDF_MATRIX_OPS:
            operands = [str(rng.uniform(-20, 20)) for _ in range(6)]

        elif new_op == "Tf":
            # operands = ["/FakeFont", str(rng.randint(1, 80))]
            operands = [ random.choice(collect_named_objects(pdf)) ]

        elif new_op == "Do":
            # operands = [f"/XObj{rng.randint(0,20)}"]

            names = collect_named_objects(pdf)
            operands = [random.choice(names)] # Add a known name to the thing...

        ops.insert(idx, (operands, new_op))
        return ops


    # ---------------------------------------------------------------
    # 3. Delete a random operator
    # ---------------------------------------------------------------
    if choice == 3 and len(ops) > 1:
        del ops[rng.randrange(len(ops))]
        return ops


    # ---------------------------------------------------------------
    # 4. Shuffle operators
    # ---------------------------------------------------------------
    if choice == 4:
        rng.shuffle(ops)
        return ops


    # ---------------------------------------------------------------
    # 5. Insert graphics state manipulation q/Q
    # ---------------------------------------------------------------
    if choice == 5:
        idx = rng.randrange(len(ops))
        ops.insert(idx, ([], rng.choice(["q", "Q"])))
        return ops


    # ---------------------------------------------------------------
    # 6. Mutate color operators
    # ---------------------------------------------------------------
    if choice == 6:
        for operands, op in ops:
            if op in PDF_COLOR_OPS:
                # random color model switching
                if op in ["rg", "RG"]:
                    operands[:] = [str(rng.random()),
                                   str(rng.random()),
                                   str(rng.random())]
                elif op in ["g", "G"]:
                    operands[:] = [str(rng.random())]
                elif op in ["k", "K"]:
                    operands[:] = [str(rng.random()) for _ in range(4)]
                elif op in ["cs", "CS"]:
                    operands[:] = ["/" + rng.choice(["DeviceRGB", "Pattern", "ICCBased"])]
                elif op in ["sc", "SC"]:
                    operands[:] = [str(rng.random()) for _ in range(rng.randint(1,4))]
        return ops


    # ---------------------------------------------------------------
    # 7. Mutate text operators
    # ---------------------------------------------------------------
    if choice == 7:
        for operands, op in ops:
            if op == "Tf":
                # change font name + size
                names = collect_named_objects(pdf)
                operands[0] = rng.choice(names) # "/" + "Font" + str(rng.randint(0,50))
                operands[1] = str(rng.uniform(1,200))
            elif op in ["Tj"]:
                # corrupt text
                operands[0] = "(" + "".join(chr(rng.randint(30,126))
                                             for _ in range(rng.randint(1,30))) + ")"
            elif op == "TJ":
                # mix numbers + strings
                operands[:] = [
                    "(" + "".join(chr(rng.randint(30,126))
                                   for _ in range(rng.randint(1,10))) + ")",
                    str(rng.uniform(-20,20)),
                    "(" + "".join(chr(rng.randint(30,126))
                                   for _ in range(rng.randint(1,10))) + ")"
                ]
        return ops


    # ---------------------------------------------------------------
    # 8. Mutate transformation matrices (cm, Tm)
    # ---------------------------------------------------------------
    if choice == 8:
        for operands, op in ops:
            if op in PDF_MATRIX_OPS:
                for i in range(len(operands)):
                    operands[i] = str(rng.uniform(-1000, 1000))
        return ops


    # ---------------------------------------------------------------
    # 9. Mutate XObject references (/Name Do)
    # ---------------------------------------------------------------
    if choice == 9:
        for operands, op in ops:
        #for i in range(len(ops)):
            # operands, op = ops[i]
            if op == "Do":
                global not_reached
                not_reached = False
                # operands[0] = "/" + "XObj" + str(rng.randint(0,200))
                names = collect_named_objects(pdf)
                new_name = rng.choice(names)
                new_name = str(new_name)
                # dprint("old name: "+str(operands[0]))
                # dprint("New name: "+str(new_name))
                # ops[i][0] = new_name # copy.deepcopy(new_name) # Collect random...
                # ops[i] = tuple((x for x in [[new_name] + list(ops[i][1:])]))
                operands[0] = new_name
                # dprint(ops[i])
        # dprint("Returning... ")
        return ops


    # ---------------------------------------------------------------
    # 10. Insert clipping operators (W/W*)
    # ---------------------------------------------------------------
    if choice == 10:
        idx = rng.randrange(len(ops))
        ops.insert(idx, ([], rng.choice(PDF_CLIP_OPS)))
        return ops


    # ---------------------------------------------------------------
    # 11. Remove/reduce operand count (operand corruption)
    # ---------------------------------------------------------------
    if choice == 11:
        entry = rng.choice(ops)
        operands, op = entry
        if operands:
            # randomly drop or duplicate operands
            if rng.random() < 0.5:
                del operands[rng.randrange(len(operands))]
            else:
                operands.append(operands[-1])
        return ops


    return ops


def serialize_ops(ops):
    out = []
    for operands, op in ops:
        out.extend(operands)
        out.append(op)
    return (" ".join(out)).encode("latin1")

def mutate_stream_inplace(stream: Stream, rng: random.Random, pdf):
    """
    Mutate stream bytes in-place (read-modify-write) using rng.
    """
    dprint("Mutating stream!!!")
    try:
        # print(stream.__dir__())
        data = bytearray(stream.read_bytes() or b"")
    except Exception as e:
        if "unfilterable" in str(e):
            data = bytearray(stream.read_raw_bytes() or b"")
        else:
            # print("Fuck!!!!")
            raise(e)
            return False
    if not data:
        # insert small content
        data = bytearray(b'\x00')

    '''
    try:
        data = stream.read_bytes() or b""
    except Exception:
        data = stream.read_raw_bytes() or b""
    '''

    # Detect & parse content stream
    if is_drawing_stream(stream):
        try:
            dprint("Saving original data...")
            fh = open("original_stream.bin", "wb")
            fh.write(data)
            fh.close()
            ops = tokenize_content_stream(data)
            if not ops:
                return False
            dprint("Mutating drawing stream...")
            fh = open("ops_before.txt", "w")
            fh.write(str(ops))
            fh.close()
            ops = mutate_operator_list(ops, rng, pdf)
            fh = open("ops_after.txt", "w")
            fh.write(str(ops))
            fh.close()
            new_data = serialize_ops(ops)
            dprint("New data: "+str(new_data))
            fh = open("new_stream.bin", "wb")
            fh.write(new_data)
            fh.close()
            stream.write(new_data)
            return True

        except Exception as exception:

            if not_reached == False:
                dprint(traceback.print_exception(type(exception), exception, exception.__traceback__))
                dprint(str(exception))
                dprint("FUCK!"*1000)
                exit(1)
            # fallback: raw mutation
            pass


    choice = rng.randrange(4)
    if choice == 0:
        pos = rng.randrange(len(data))
        data[pos] ^= 0xFF
    elif choice == 1:
        pos = rng.randrange(len(data))
        for _ in range(rng.randrange(MAX_CHAR_INSERT_COUNT)):
            data.insert(pos, rng.randrange(256))
    elif choice == 2:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randint(1, min(10000, len(data))))
        del data[start:end]
    else:
        # duplicate a small slice
        if len(data) >= 2:
            start = rng.randrange(len(data)-1)
            end = start + rng.randint(1, min(10000, len(data)-start)) # rng.randint(1, min(8, len(data)-start))
            slicev = data[start:end]
            where = rng.randrange(len(data))
            data = data[:where] + slicev + data[where:]
    
    if rng.random() < 0.05 and len(data) > 100:
        start = rng.randrange(len(data)-50)

        block = data[start: rng.randrange(start, len(data))] # Do the stuff here...

        # data += block * rng.randrange(5, 40)

        pos = rng.randrange(len(data))

        data = data[:pos] + block * rng.randrange(5,100) + data[pos:] # Insert the thing...
    
    try:
        if rng.randrange(10) == 9: # Check for the multiplication of the stream...
            dprint("Multiplying stream!!!")
            data = data * rng.randrange(MAX_STRING_MULT_COUNT)
        stream.write(bytes(data))
        return True
    except Exception as e:
        raise(e)
        return False


def choose_target_object(pdf: pikepdf.Pdf, rng: random.Random):
    candidates = []
    for i, obj in enumerate(pdf.objects):
        try:
            if isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary, pikepdf.Array)) and not is_critical_object(obj, pdf): # Originally did not have pikepdf.Array
                candidates.append(tuple((obj, i)))
        except Exception:
            continue
    if not candidates:
        return None
    return rng.choice(candidates)


def construct_pike_replacement(py_sample: Dict[str, Any], pdf: pikepdf.Pdf):
    """
    Convert py sample to pike object (or stream-construction marker).
    """
    return py_to_pike(py_sample, pdf=pdf)


def replace_object_with_sample(pdf: pikepdf.Pdf, target_obj, sample_py, rng: random.Random):
    """
    Replace target_obj inline in pdf with sample_py converted.
    Returns True on success. Raises on unsupported cases.
    """
    dprint("Replacing object...")

    constructed = construct_pike_replacement(sample_py, pdf)

    dprint("constructed: "+str(constructed))
    dprint("target object: "+str(target_obj))
    # Helper to clear dictionary keys safely
    def clear_dict(d):
        for k in list(d.keys()):
            try:
                del d[k]
            except Exception:
                pass

    # Stream target
    if isinstance(target_obj, pikepdf.Stream):
        if isinstance(constructed, dict) and "__construct_stream__" in constructed:
            meta = constructed["__construct_stream__"]["dict"]
            data = constructed["__construct_stream__"]["bytes"]
            # remove all metadata except banned keys
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    pass
            # write new bytes and metadata
            target_obj.write(data)
            for kk, vv in meta.items():
                # kk is a Name object in the marker; ensure no banned keys
                kk_str = str(kk) if not isinstance(kk, str) else kk
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    # if vv is a pike object already or py-serializable
                    target_obj[Name(kk_str if kk_str.startswith("/") else "/" + kk_str)] = vv
                except Exception:
                    try:
                        target_obj[Name(kk_str if kk_str.startswith("/") else "/" + kk_str)] = py_to_pike(vv, pdf=pdf)
                    except Exception:
                        dprint("Exception!!!")
                        pass
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # rewrite bytes and copy allowed metadata
            data = constructed.read_bytes() or b""
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    dprint("Exception!!!")
                    pass
            target_obj.write(data)
            for kk, vv in constructed.items():
                kk_str = str(kk)
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    target_obj[kk] = vv
                except Exception:
                    try:
                        target_obj[kk] = py_to_pike(pike_to_py(vv), pdf=pdf)
                    except Exception:
                        dprint("Exception!!!")
                        pass
            return True
        elif isinstance(constructed, pikepdf.Dictionary):
            # convert dictionary to stream's metadata with empty bytes
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    dprint("Exception!!!")
                    pass
            target_obj.write(b"")
            for kk, vv in constructed.items():
                kk_str = str(kk)
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    target_obj[kk] = vv
                except Exception:
                    dprint("Exception!!!")
                    pass
            return True
        elif isinstance(constructed, pikepdf.Array):
            # Do the stuff here...
            target_obj = constructed
            return True
        else:
            raise RuntimeError("Unsupported constructed type for stream replacement: %r" % type(constructed))

    # Dictionary target
    elif isinstance(target_obj, pikepdf.Dictionary):
        if isinstance(constructed, pikepdf.Dictionary):
            clear_dict(target_obj)
            for kk, vv in constructed.items():
                try:
                    target_obj[kk] = vv
                except Exception:
                    try:
                        target_obj[kk] = py_to_pike(pike_to_py(vv), pdf=pdf)
                    except Exception:
                        dprint("Exception!!!")
                        pass
            return True
        elif isinstance(constructed, dict) and "__construct_stream__" in constructed:
            clear_dict(target_obj)
            meta = constructed["__construct_stream__"]["dict"]
            for kk, vv in meta.items():
                kk_str = str(kk) if not isinstance(kk, str) else kk
                kname = Name(kk_str if kk_str.startswith("/") else "/" + kk_str)
                try:
                    target_obj[kname] = vv
                except Exception:
                    try:
                        target_obj[kname] = py_to_pike(vv, pdf=pdf)
                    except Exception:
                        dprint("Exception!!!")
                        pass
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # copy stream's stream_dict entries into dict
            clear_dict(target_obj)
            for kk, vv in constructed.items():
                try:
                    target_obj[kk] = vv
                except Exception:
                    dprint("Exception!!!")
                    pass
            return True
        elif isinstance(constructed, pikepdf.Array):
            # Array shit...
            target_obj = constructed # Just assign that shit there...
        else:
            raise RuntimeError("Unsupported constructed type for dict replacement: %r" % type(constructed))


    elif isinstance(target_obj, pikepdf.Array): # Array type...

        target_obj = constructed # Just assign that shit???
        return True
    else:
        dprint("Here is the object: "+str(target_obj))
        dprint("The type thing: "+str(type(target_obj)))
        raise RuntimeError("Unsupported target_obj type: %r" % type(target_obj))


# -----------------------------
# Mutate whole PDF bytes (combining replacement + in-place edits)
# -----------------------------
def mutate_pdf_structural(buf: bytes, max_size: int, rng: random.Random) -> bytes:
    """
    Parse the PDF, choose a target object and perform:
      - replacement (sample from resources DB) OR
      - in-place mutation of object (dict/stream) OR
      - shuffle pages
    Decisions are deterministic from rng.
    Raises on parse/convert errors (no silent fallback).
    """

    if rng.random() < 0.2: # 20 percent chance to just mutate randomly the thing...
        res = mutate_pdf_in_memory(buf, rng.randrange(1,1000000)) # data, seed
        assert isinstance(res, bytes) # Should be bytes...
        if len(res) >= max_size:
            res = res[:max_size] # Maximum size...
        return res # Return the result...



    try:
        pdf = pikepdf.open(io.BytesIO(buf))
    except Exception as e:
        raise RuntimeError("pikepdf failed to open input: %s" % e)

    if not _resources_db:
        raise RuntimeError("empty resources DB")


    # for _ in range(rng.randrange(MAX_MUTATIONS)):


    # Decide action: weights
    # 0-49 => replace object (50%)
    # 50-79 => mutate object in-place (30%)
    # 80-99 => shuffle/structural (20%)
    action_roll = rng.randrange(100)

    # Replacement path
    if action_roll < 50:
        target, _ = choose_target_object(pdf, rng)
        if target is None:
            raise RuntimeError("no candidate objects found for replacement")
        sample_py = rng.choice(_resources_db)
        ok = replace_object_with_sample(pdf, target, sample_py, rng)
        if not ok:
            raise RuntimeError("replacement failed")
    # In-place mutation path
    elif action_roll < 100:
        target, target_index = choose_target_object(pdf, rng)
        if target is None:
            raise RuntimeError("no candidate objects found for in-place mutation")
        if isinstance(target, pikepdf.Stream):
            ok = mutate_stream_inplace(target, rng, pdf)
            if not ok:
                raise RuntimeError("stream mutate failed")
        elif isinstance(target, pikepdf.Dictionary):
            ok = False
            count = 10
            for i in range(count):
                ok = mutate_dict_inplace(target, rng, pdf=pdf)
                if ok:
                    break
                # else:
                #     dprint("Dictionary mutation failed!!!")
                #     exit(1)
        elif isinstance(target, pikepdf.Array): # Mutate array
            dprint("Before target: "+str(target))
            new_array = mutate_array(target, rng, pdf=pdf) # Mutate the thing...
            dprint("The mutate_array returned this object here: "+str(new_array))
            pdf.objects[target_index] = new_array # assign..
            dprint("After mutate_array target: "+str(pdf.objects[target_index]))
            # if ok:
            #     break
        else:
            dprint("FUCK!")
            dprint("Invalid target for inplace mutation: "+str(target))
            exit(1)
    # Structural / page operations
    else:
        # shuffle pages occasionally
        pages = list(pdf.pages)
        if len(pages) > 1:
            # deterministic shuffle by rng
            perm = list(range(len(pages)))
            # perform a small number of swaps depending on rng
            swap_count = 1 + (rng.randrange(min(5, len(pages))))
            for _ in range(swap_count):
                i = rng.randrange(len(pages))
                j = rng.randrange(len(pages))
                perm[i], perm[j] = perm[j], perm[i]
            # apply permutation
            new_pages = [pages[i] for i in perm]
            # pdf.pages.clear()
            for p in new_pages:
                pdf.pages.append(p)
        else:
            # fallback structural edit: replace resources object if present
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Dictionary) and (set(k.strip("/") for k in obj.keys()) & {"Font", "XObject"}):
                        sample_py = rng.choice(_resources_db)
                        replace_object_with_sample(pdf, obj, sample_py, rng)
                        break
                except Exception:
                    pass

    # Save mutated PDF to bytes
    out_buf = io.BytesIO()
    try:
        pdf.save(out_buf, linearize=False, compress_streams=False)
    except Exception as e:
        raise RuntimeError("pikepdf.save failed: %s" % e)
    # print("taddaaaaaaaa"*100) # Debug print...
    data = out_buf.getvalue()
    if len(data) > max_size:
        data = data[:max_size]
    return data


# -----------------------------
# Generic fallback mutator (kept but NOT used as fallback per request)
# -----------------------------
def remove_substring(b: bytes, rng: random.Random) -> bytes:
    if len(b) < 2:
        return b
    start = rng.randrange(len(b)-1)
    end = rng.randrange(start+1, len(b))
    return b[:start] + b[end:]


def multiply_substring(b: bytes, rng: random.Random) -> bytes:
    if len(b) < 2:
        return b
    start = rng.randrange(len(b)-1)
    end = rng.randrange(start+1, len(b))
    substr = b[start:end]
    where = rng.randrange(len(b))
    return b[:where] + substr * (1 + rng.randrange(4)) + b[where:]


def add_character(b: bytes, rng: random.Random) -> bytes:
    where = rng.randrange(len(b)) if b else 0
    return b[:where] + bytes([rng.randrange(256)]) + b[where:]


def mutate_generic(b: bytes, rng: random.Random) -> bytes:
    if not b:
        return bytes([rng.randrange(256)])
    choice = rng.randrange(3)
    if choice == 0:
        return remove_substring(b, rng)
    elif choice == 1:
        return multiply_substring(b, rng)
    else:
        return add_character(b, rng)


# -----------------------------
# AFL++ API: init / deinit / fuzz_count / fuzz
# -----------------------------
def init(seed: int):
    """
    Called once by AFL at startup with a seed.
    We load resources DB but do NOT use the provided seed for per-input mutation randomness.
    """
    global _initialized, _resources_db, _mutation_count

    if _initialized:
        return

    # Load resources DB from pickle or PDF dir
    try:
        #while True:
        #    dlog("Paskaaaaa!!!!!")
        _resources_db = load_resources_db(DEFAULT_PDF_DIR, DEFAULT_PKL_PATH)
        if len(_resources_db) == 0:
            exit(0)
    except Exception as e:
        print("Warning: load_resources_db failed: %s" % e, file=sys.stderr)
        dlog("Warning: load_resources_db failed: %s" % e)
        exit(0)
        _resources_db = []

    _initialized = True
    return


def deinit():
    global _initialized
    _initialized = False


def fuzz_count(buf: bytearray) -> int:
    """
    Return how many fuzz cycles to perform for this buffer.
    If the buffer cannot be parsed as a PDF (pikepdf), return 0 to skip mutating.
    """
    if not isinstance(buf, (bytes, bytearray)):
        return 0
    if len(buf) <= HEADER_SIZE:
        return 0
    # attempt to parse PDF (exclude header)
    try:
        core = bytes(buf[HEADER_SIZE:])
        with pikepdf.open(io.BytesIO(core)) as pdf:
            # open succeeded; schedule mutations
            return _mutation_count
    except Exception:
        # invalid PDFs we don't attempt to mutate structurally
        return 0


def fuzz(buf: bytearray, add_buf, max_size: int) -> bytearray:
    """
    Perform a single mutation. buf is bytes/bytearray input.
    Preserve HEADER_SIZE bytes and mutate the rest.
    Raises on structural failure (no silent fallback).
    """

    try:

        if not _initialized:
            raise RuntimeError("mutator not initialized; call init(seed) before fuzz()")

        if not isinstance(buf, (bytes, bytearray)):
            raise ValueError("buf must be bytes or bytearray")

        if len(buf) <= HEADER_SIZE:
            raise ValueError("buf too small (<= HEADER_SIZE)")

        header = bytes(buf[:HEADER_SIZE])
        core = bytes(buf[HEADER_SIZE:])

        rng = rng_from_buf(bytes(buf))  # deterministic RNG from buffer

        mutated_core = mutate_pdf_structural(core, max_size - HEADER_SIZE, rng)
        out = bytearray()
        out.extend(header)
        out.extend(mutated_core)
        if len(out) > max_size:
            out = out[:max_size]
        return out
    except Exception as exception:

        # print("Encountered this bullshit exception...")
        # print(e)
        
        '''
        if DEBUG:

            if "unable to find" not in str(exception) and "root" not in str(exception):
                # print(str(e))
                dprint(str(exception))
                dprint(traceback.print_exception(type(exception), exception, exception.__traceback__))
                assert False
                exit(1)
        '''

        # raise e
        # return 
        return generic_mutator_bytes.mutate_generic(bytes(buf))



# -----------------------------
# CLI helpers for maintenance (build pkl / test)
# -----------------------------
def cli_build_db(pdf_dir: str = None, pkl_path: str = None):
    pdf_dir = Path(pdf_dir or DEFAULT_PDF_DIR)
    pkl_path = Path(pkl_path or DEFAULT_PKL_PATH)
    db = build_resources_db_from_dir(pdf_dir, pkl_path)
    print(f"Built DB with {len(db)} samples; saved to {pkl_path}")


def cli_mutate_file(infile: str, outfile: str, times: int = 1):
    """
    Quick test: mutate a PDF file deterministically using its own bytes as seed.
    """
    with open(infile, "rb") as fh:
        data = fh.read()
    if len(data) <= HEADER_SIZE:
        data = (b"\x00" * HEADER_SIZE) + data
    else:
        data = b"\x00\x00\x00\x00" + data

    for i in range(times):
        mutated = fuzz(bytearray(data), None, 10_000_000)
        data = bytes(mutated)
        # with open(f"{outfile}.{i}", "wb") as fh:
        #     fh.write(data)
    with open(outfile, "wb") as fh:
        fh.write(data)
    # print(f"Wrote mutated output to {outfile}")

# Needed for libfuzzer
def custom_mutator(buf: bytearray, add_buf, max_size: int, callback=None) -> bytearray:
    """
    Python entrypoint for LLVMFuzzerCustomMutator.
    Mirrors the AFL++-style fuzz(buf, add_buf, max_size) signature.

    buf: current input as bytes/bytearray
    add_buf: optional secondary buffer (may be None)
    max_size: maximum allowed output size
    """

    # Log every call for debugging
    '''
    try:
        with open("custom_mutator.log", "a") as log:
            log.write("custom_mutator called\n")
    except Exception:
        pass  # don't fail due to logging issues
    '''

    # Make sure the mutator is initialized
    if not _initialized:
        init(0)

    # Just delegate to the main fuzz() implementation
    try:
        mutated = fuzz(buf, add_buf, max_size)
        fh = open("mutated.pdf", "wb")
        fh.write(mutated)
        fh.close()
        return mutated # fuzz(buf, add_buf, max_size)
    except Exception as e:
        # Log the error as well, so you know if something went wrong
        try:
            with open("custom_mutator.log", "a") as log:
                log.write(f"custom_mutator exception: {e}\n")
        except Exception:
            pass
        # On error, return the original buffer (safe fallback)
        return buf

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Mutator maintenance / testing")
    ap.add_argument("--build-db", action="store_true", help="Build resources.pkl from MUTATOR_PDF_DIR")
    ap.add_argument("--pdf-dir", default=str(DEFAULT_PDF_DIR))
    ap.add_argument("--pkl-path", default=str(DEFAULT_PKL_PATH))
    ap.add_argument("--mutate", nargs=2, metavar=("IN", "OUT"), help="Mutate IN -> OUT (single pass)")
    ap.add_argument("--mutate-iter", nargs=3, metavar=("IN", "OUT", "N"), help="Mutate IN repeatedly N times")
    ap.add_argument("--run-until", nargs=2, metavar=("IN", "OUT"), help="Run until the specified point in the code...") # Do the stuff..
    args = ap.parse_args()

    if args.build_db:
        cli_build_db(args.pdf_dir, args.pkl_path)
        sys.exit(0)

    if args.mutate:
        infile, outfile = args.mutate
        init(0)
        try:
            cli_mutate_file(infile, outfile, times=1)
        except Exception as e:
            print("Mutation error: " + str(e))
            traceback.print_exc()
        sys.exit(0)

    if args.mutate_iter:
        infile, outfile, n = args.mutate_iter
        n = int(n)
        init(0)
        try:
            # while not_reached:
            cli_mutate_file(infile, outfile, times=n)
        except Exception as e:
            print("Mutation error: " + str(e))
            traceback.print_exc()
        sys.exit(0)

    if args.run_until:
        # if args.mutate_iter:
        infile, outfile = args.run_until
        # n = int(n)
        init(0)
        try:
            while not_reached:
                cli_mutate_file(infile, outfile, times=1)
        except Exception as e:
            print("Mutation error: " + str(e))
            traceback.print_exc()
        dprint("exiting...")
        sys.exit(0)

    print("No action specified. This script is the AFL++ custom mutator module.")
