
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>

// #include "third_party/base/check_op.h"

using namespace std;


// Helper: pad number to 10 digits
static std::string Pad10(size_t v) {
    std::ostringstream oss;
    oss << std::setw(10) << std::setfill('0') << v;
    return oss.str();
}

std::string MakePDFWithText(const std::string& newText) {
    // Template with placeholders for text & length.
    std::string pdf =
R"(%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200]
   /Resources << /Font << /F1 4 0 R >> >>
   /Contents 5 0 R >>
endobj

4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

5 0 obj
<< /Length XXXXX >>
stream
BT
/F1 0.1 Tf
50 100 Td
(TEXTPLACEHOLDER) Tj
ET
endstream
endobj

xref
0 6
XXXXXXXXXX 65535 f
XXXXXXXXXX 00000 n
XXXXXXXXXX 00000 n
XXXXXXXXXX 00000 n
XXXXXXXXXX 00000 n
XXXXXXXXXX 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
YYYYYY
%%EOF
)";

    // -----------------------------------------------------
    // 1) Insert the text inside the stream
    // -----------------------------------------------------
    size_t pos = pdf.find("(TEXTPLACEHOLDER)");
    if (pos == std::string::npos)
        return ""; // should not happen

    pdf.replace(pos, strlen("(TEXTPLACEHOLDER)"),
                "(" + newText + ")");

    // -----------------------------------------------------
    // 2) Recompute /Length XXXX
    // -----------------------------------------------------
    size_t streamPos = pdf.find("stream");
    size_t endStreamPos = pdf.find("endstream");

    if (streamPos == std::string::npos || endStreamPos == std::string::npos)
        return "";

    streamPos += strlen("stream\n"); // skip to content

    size_t length = endStreamPos - streamPos;

    // Replace XXXXX
    size_t lenPos = pdf.find("/Length");
    size_t lenStart = pdf.find("XXXXX", lenPos);
    pdf.replace(lenStart, 5, std::to_string(length));

    // -----------------------------------------------------
    // 3) Recompute xref offsets
    // -----------------------------------------------------
    // Object numbers: 0-5 (we only record for 1-5)
    std::vector<size_t> offsets(6, 0);

    for (int obj = 1; obj <= 5; obj++) {
        std::string marker = std::to_string(obj) + " 0 obj";
        size_t offset = pdf.find(marker);
        if (offset == std::string::npos) return "";
        offsets[obj] = offset;
    }

    // Replace 0..5 xref entries
    size_t xrefPos = pdf.find("xref");
    if (xrefPos == std::string::npos)
        return "";

    // Format:
    // 0000000000 65535 f
    // 0000000010 00000 n
    // etc…

    // First entry (free object)
    size_t posFree = pdf.find("XXXXXXXXXX 65535 f");
    pdf.replace(posFree, 10, Pad10(offsets[0]));

    // Live objects
    int currentObj = 1;
    size_t search = posFree + 1;

    while (currentObj <= 5) {
        search = pdf.find("XXXXXXXXXX 00000 n", search);
        if (search == std::string::npos) return "";

        pdf.replace(search, 10, Pad10(offsets[currentObj]));
        currentObj++;
        search += 5;
    }

    // -----------------------------------------------------
    // 4) Recompute startxref
    // -----------------------------------------------------
    size_t startxrefPos = pdf.find("startxref");
    if (startxrefPos == std::string::npos)
        return "";

    size_t numberPos = pdf.find("YYYYYY", startxrefPos);
    size_t xrefRealOffset = xrefPos;

    pdf.replace(numberPos, 6, std::to_string(xrefRealOffset));

    return pdf;
}



int main(int argc, char** argv) {
    // Stuff...
    cout << MakePDFWithText("stuff");
    return 0;
}
