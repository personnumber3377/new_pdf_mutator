

'''
<<
/FunctionType 0
/BitsPerSample 8
/Length 5
/Range [0 1]
/Domain [0 1]
/Size [5]
/Type /Function
>>
stream
ÿÿÿ
'''

'''

12 0 obj
<<
/FunctionType 0
/BitsPerSample {{INT_FUZZ:bps}}        % fuzz BPS (8, 12, 16, 24, 32)
/Size [ {{INT_FUZZ:size0}} ]           % fuzz sample count (1–32)
/Range [ {{FLOAT_FUZZ:r0}} {{FLOAT_FUZZ:r1}} ]
/Domain [ {{FLOAT_FUZZ:d0}} {{FLOAT_FUZZ:d1}} ]
/Type /Function
/Length {{LEN:function_stream}}        % exact length matches fuzz stream
>>
stream
{{BYTES:function_stream:4096}}         % large enough to satisfy Size × BPS
endstream
endobj
'''

payload = b"\x07" # 7 index is the samplefunc...
payload += b"\x00\x00\x00\x08" # sample count 8
payload += b"\x00\x00\x00\x05" # size 5

payload += b"\x00\x00\x00\x00" # range[0] == 1
payload += b"\x00\x00\x00\x01" # range[1] == 0

payload += b"\x00\x00\x00\x00" # range[0] == 1
payload += b"\x00\x00\x00\x01" # range[1] == 0

payload += b"\xff\xff\xff\x00\x00" # The stuff...

# Do the stuff...

fh = open("payload.bin", "wb")
fh.write(payload)
fh.close()


