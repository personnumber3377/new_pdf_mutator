import sys
import struct

# Helper to pack floats
def pack_float(f):
    return struct.pack('>f', f) # Big-endian

def pack_int(i, bits):
    num_bytes = (bits + 7) // 8
    return i.to_bytes(num_bytes, byteorder='big')

# PDF Structure
large_pos_float = 3.402823466e+38
large_neg_float = -3.402823466e+38

func_stream_content = b'{ dup } % Simple function: input -> input'
func_stream = b'''
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length %d
>>
stream
%s
endstream
''' % (len(func_stream_content), func_stream_content)

# Stream data for one Coons patch (Type 6)
# Flag (8 bits): 0 (start of patch)
# Coords (32 bits * 2) * 12 points
# Color (8 bits * 1) * 4 points

flag0 = pack_int(0, 8) # Start patch

# Define 12 coordinates (simple square 0,0 to 1,1)
coords = b''
coords += pack_float(0.0) + pack_float(0.0) # Pt 0
coords += pack_float(0.3) + pack_float(0.0) # Pt 1 (Control)
coords += pack_float(0.7) + pack_float(0.0) # Pt 2 (Control)
coords += pack_float(1.0) + pack_float(0.0) # Pt 3
coords += pack_float(1.0) + pack_float(0.3) # Pt 4 (Control)
coords += pack_float(1.0) + pack_float(0.7) # Pt 5 (Control)
coords += pack_float(1.0) + pack_float(1.0) # Pt 6
coords += pack_float(0.7) + pack_float(1.0) # Pt 7 (Control)
coords += pack_float(0.3) + pack_float(1.0) # Pt 8 (Control)
coords += pack_float(0.0) + pack_float(1.0) # Pt 9
coords += pack_float(0.0) + pack_float(0.7) # Pt 10 (Control)
coords += pack_float(0.0) + pack_float(0.3) # Pt 11 (Control)

# Define 4 colors
color0 = pack_int(255, 8) # Causes NaN
color1 = pack_int(0, 8)   # Causes NaN
color2 = pack_int(0, 8)   # Causes NaN
color3 = pack_int(0, 8)   # Causes NaN

colors = color0 + color1 + color2 + color3

# Combine vertex stream data: Flag | Coords | Colors
vertex_stream_content = flag0 + coords + colors
# 8 + (32*2*12) + (8*1*4) = 8 + 768 + 32 = 808 bits = 101 bytes.




float_vals = b"\x00"*4 + b"\x00"*4 # The two floats...

fh = open("vertex_stream.bin", "wb")
fh.write(float_vals+vertex_stream_content)
fh.close()

# fh.write(data)

shading_dict_content = b'''
<<
  /ShadingType 6
  /ColorSpace /DeviceRGB
  /BitsPerCoordinate 32
  /BitsPerComponent 8
  /BitsPerFlag 8
  /Decode [ 0 1 0 1 %f %f ]
  /Function %d 0 R
  /Length %d
>>
stream
%s
endstream
''' % (large_neg_float, large_pos_float, 6, len(vertex_stream_content), vertex_stream_content)

# --- PDF Objects ---
catalog_obj = b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj'
pages_obj = b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj'
page_obj = b'''
3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj
'''
shading_obj = b'4 0 obj\n' + shading_dict_content + b'\nendobj'
contents_obj = b'''
5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj
'''
function_obj = b'6 0 obj\n' + func_stream + b'\nendobj'

# --- XRef Table & Trailer ---
xref_entries = []
xref_entries.append(b'0000000000 65535 f ') # Obj 0

pdf_body = b'\n'.join([
catalog_obj,
pages_obj,
page_obj,
shading_obj,
contents_obj,
function_obj
])

header = b'%PDF-1.7\n%\xc2\xa5\xc2\xb1\xc3\xab\xc3\xbf'

# Calculate xref offsets
offset = len(header) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 1
offset += len(catalog_obj) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 2
offset += len(pages_obj) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 3
offset += len(page_obj) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 4
offset += len(shading_obj) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 5
offset += len(contents_obj) + 1
xref_entries.append(f'{offset:010d} 00000 n '.encode()) # Obj 6
offset += len(function_obj) + 1

xref_table = b'xref\n0 7\n' + b'\n'.join(xref_entries) + b'\n'

trailer = b'''
trailer
<< /Size 7 /Root 1 0 R >>
startxref
%d
%%EOF
''' % offset

program_input = header + b'\n' + pdf_body + b'\n' + xref_table + trailer
sys.stdout.buffer.write(program_input) 

