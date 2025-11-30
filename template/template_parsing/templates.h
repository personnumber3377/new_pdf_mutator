
// This file here contains all of the different pdf fuzzing templates which we need to fuzz the pdfium stuff...



const char kShadingTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj

<<
  /ShadingType 6
  /ColorSpace /DeviceRGB
  /BitsPerCoordinate 32
  /BitsPerComponent 8
  /BitsPerFlag 8
  /Decode [ 0 1 0 1 {{FLOAT_FUZZ:decode_floats}} {{FLOAT_FUZZ:decode_floats}} ]
  /Function 6 0 R
  /Length {{LEN:mesh_stream}}
>>
stream
{{BYTES:mesh_stream:10000}}
endstream

endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj

<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup } % Simple function: input -> input
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 

trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";

const char kGouraudShadingTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj

<<
  /ShadingType 4
  /ColorSpace /DeviceRGB
  /BitsPerCoordinate 32
  /BitsPerComponent 8
  /BitsPerFlag 8
  /Decode [ {{FLOAT_FUZZ:decode_floats}} {{FLOAT_FUZZ:decode_floats}} {{FLOAT_FUZZ:decode_floats}} {{FLOAT_FUZZ:decode_floats}} 0 1 ]
  /Function 6 0 R
  /Length {{LEN:mesh_stream}}
>>
stream
{{BYTES:mesh_stream:10000}}
endstream

endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj

<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup } % Simple function: input -> input
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 

trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";

const char kFuncShadingTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj
<<
  /ShadingType 1
  /ColorSpace /DeviceRGB
  /Domain [ {{FLOAT_FUZZ:domain1}} {{FLOAT_FUZZ:domain2}} ]
  /BBox [ {{FLOAT_FUZZ:b0}} {{FLOAT_FUZZ:b1}} {{FLOAT_FUZZ:b2}} {{FLOAT_FUZZ:b3}} ]
  /Function 6 0 R
>>
endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup }
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 

trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";

const char kAxialShadingTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj
<<
  /ShadingType 2
  /ColorSpace /DeviceRGB
  /Coords [ {{FLOAT_FUZZ:c0}} {{FLOAT_FUZZ:c1}} {{FLOAT_FUZZ:c2}} {{FLOAT_FUZZ:c3}} ]
  /Domain [ 0 1 ]
  /Function 6 0 R
  /Extend [ true true ]
>>
endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup }
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";




const char kRadialShadingTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj
<<
  /ShadingType 3
  /ColorSpace /DeviceRGB
  /Coords [
    {{FLOAT_FUZZ:x0}} {{FLOAT_FUZZ:y0}} {{FLOAT_FUZZ:r0}}
    {{FLOAT_FUZZ:x1}} {{FLOAT_FUZZ:y1}} {{FLOAT_FUZZ:r1}}
  ]
  /Domain [ 0 1 ]
  /Function 6 0 R
>>
endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup }
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";



const char kLatticeGouraudTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj
<<
  /ShadingType 5
  /ColorSpace /DeviceRGB
  /BitsPerCoordinate 32
  /BitsPerComponent 8
  /Decode [
    {{FLOAT_FUZZ:d0}} {{FLOAT_FUZZ:d1}}
    {{FLOAT_FUZZ:d2}} {{FLOAT_FUZZ:d3}}
    0 1
  ]
  /VerticesPerRow {{UINT32BE:vpr}}
  /Function 6 0 R
  /Length {{LEN:mesh_stream}}
>>
stream
{{BYTES:mesh_stream:20000}}
endstream

endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup }
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";





const char kTensorPatchTemplate[] = R"(
%PDF-1.7
%¥±ëÿ
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 200 200]
  /Resources << /Shading << /Sh0 4 0 R >> >>
  /Contents 5 0 R
>>
endobj

4 0 obj
<<
  /ShadingType 7
  /ColorSpace /DeviceRGB
  /BitsPerCoordinate 32
  /BitsPerComponent 8
  /BitsPerFlag 8
  /Decode [
    0 1
    0 1
    {{FLOAT_FUZZ:d0}} {{FLOAT_FUZZ:d1}}
    {{FLOAT_FUZZ:d2}} {{FLOAT_FUZZ:d3}}
  ]
  /Function 6 0 R
  /Length {{LEN:mesh_stream}}
>>
stream
{{BYTES:mesh_stream:20000}}
endstream

endobj

5 0 obj
<< /Length 14 >>
stream
q /Sh0 sh Q
endstream
endobj

6 0 obj
<<
  /FunctionType 4
  /Domain [0 1]
  /Range [0 1 0 1 0 1]
  /Length 41
>>
stream
{ dup }
endstream

endobj
xref
0 7
0000000000 65535 f 
0000000019 00000 n 
0000000068 00000 n 
0000000125 00000 n 
0000000267 00000 n 
0000000663 00000 n 
0000000726 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
startxref
878
%EOF
)";





// This template here is for the shading function fuzzing... There is a very interesting UNSAFE_TODO block inside the thing...

const char kSampledFuncShadingTemplate[] = R"(
%PDF-1.4
%âãÏÓ

1 0 obj
<<
/Pages 2 0 R
/Type /Catalog
>>
endobj

2 0 obj
<<
/Kids [3 0 R]
/Type /Pages
/Count 1
>>
endobj

3 0 obj
<<
/Parent 2 0 R
/MediaBox 4 0 R
/Resources
<<
/ExtGState
<<
/CBG 5 0 R
/CBK 6 0 R
>>
/XObject
<<
/CBN 7 0 R
>>
>>
/Type /Page
/Contents 8 0 R
>>
endobj

4 0 obj [-270 -95 270 95]
endobj

5 0 obj
<<
/Name /CBG
/Type /ExtGState
/SMask
<<
/G 9 0 R
/Type /Mask
/S /Luminosity
>>
>>
endobj

6 0 obj
<<
/Name /CBK
/Type /ExtGState
/SMask
<<
/G 10 0 R
/Type /Mask
/S /Luminosity
>>
>>
endobj

7 0 obj
<<
/Group
<<
/CS /DeviceRGB
/S /Transparency
>>
/Subtype /Form
/Length 61
/Resources
<<
/ExtGState
<<
/A 11 0 R
>>
>>
/Name /CBN
/FormType 1
/BBox 4 0 R
/Type /XObject
>>
stream
q /A gs
2.5 w
0 0.5 1 RG
1 0.25 0 rg -175 -55 350 110 re B
Q
endstream
endobj

8 0 obj
<< /Length 81 >>
stream
/CBG gs 0.5 0.8 0.5 rg -270 -95 540 190 re f
/CBK gs
q 1 0 0 1 0 0 cm
/CBN Do
Q
endstream
endobj

% ==========================================================
% ============ FUZZED FUNCTION =============================
% ==========================================================

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

% ==========================================================
% ============ SHADING USING THE FUNCTION ==================
% ==========================================================

13 0 obj
<<
/ColorSpace /DeviceGray
/Function 12 0 R
/Coords [-270 0 270 0]
/ShadingType 2
/Name /CBD
/BBox 4 0 R
>>
endobj

% ==========================================================
% ============ MASK GRAPHICS OBJECT ========================
% ==========================================================

9 0 obj
<<
/Group
<<
/CS /DeviceGray
/S /Transparency
>>
/Subtype /Form
/Length 7
/Resources
<<
/Shading
<<
/CBD 13 0 R
>>
>>
/Name /CBF
/FormType 1
/BBox 4 0 R
/Type /XObject
>>
stream
/CBD sh
endstream
endobj

% ==========================================================
% ============ SECOND SHADING INSTANCE =====================
% ==========================================================

14 0 obj
<<
/ColorSpace /DeviceGray
/Function 12 0 R
/Coords [270 0 -270 0]
/ShadingType 2
/Name /CBH
/BBox 4 0 R
>>
endobj

10 0 obj
<<
/Group
<<
/CS /DeviceGray
/S /Transparency
>>
/Subtype /Form
/Length 7
/Resources
<<
/Shading
<<
/CBH 14 0 R
>>
>>
/Name /CBJ
/FormType 1
/BBox 4 0 R
/Type /XObject
>>
stream
/CBH sh
endstream
endobj

11 0 obj
<<
/CA 0.75
/Name /CBL
/Type /ExtGState
>>
endobj

xref
0 15
0000000000 65535 f
0000000015 00000 n
0000000066 00000 n
0000000125 00000 n
0000000291 00000 n
0000000325 00000 n
0000000426 00000 n
0000000528 00000 n
0000000799 00000 n
0000001203 00000 n
0000001546 00000 n
0000001764 00000 n
0000000933 00000 n
0000001077 00000 n
0000001420 00000 n

trailer
<<
/Root 1 0 R
/Size 15
>>
startxref
1824
%%EOF
)";










static const char* kAllShadingTemplates[] = {
    kFuncShadingTemplate,
    kAxialShadingTemplate,
    kRadialShadingTemplate,
    kGouraudShadingTemplate,
    kLatticeGouraudTemplate,
    kShadingTemplate,        // Coons
    kTensorPatchTemplate,
    kSampledFuncShadingTemplate
};

static const size_t kNumTemplates = sizeof(kAllShadingTemplates) / sizeof(kAllShadingTemplates[0]);

