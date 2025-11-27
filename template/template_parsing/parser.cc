#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <iostream>

#include <unistd.h>

struct SegmentInfo {
  size_t offset;
  size_t length;
};

// Trim helper
static std::string Trim(const std::string& s) {
  size_t start = 0;
  while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
    ++start;
  size_t end = s.size();
  while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
    --end;
  return s.substr(start, end - start);
}

// Split on single char
static std::vector<std::string> Split(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == delim) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

// Main template application function.
std::string ApplyPdfTemplate(const std::string& tmpl,
                             const uint8_t* data,
                             size_t data_size) {
  std::unordered_map<std::string, SegmentInfo> segments;
  size_t data_pos = 0;
  std::string out;
  out.reserve(tmpl.size() + data_size);  // heuristic

  size_t i = 0;
  while (i < tmpl.size()) {
    if (i + 1 < tmpl.size() && tmpl[i] == '{' && tmpl[i + 1] == '{') {
      // Find closing "}}"
      size_t end = tmpl.find("}}", i + 2);
      if (end == std::string::npos) {
        throw std::runtime_error("Unclosed {{ in template");
      }
      std::string inside = tmpl.substr(i + 2, end - (i + 2));
      inside = Trim(inside);

      // Advance past token
      i = end + 2;

      if (inside.empty()) {
        continue;
      }

      // Parse token: OP:arg1:arg2...
      std::vector<std::string> parts = Split(inside, ':');
      for (auto& p : parts) p = Trim(p);
      if (parts.empty())
        continue;

      const std::string& op = parts[0];

      if (op == "BYTES") {
        // {{BYTES:name:N}}
        if (parts.size() != 3) {
          throw std::runtime_error("BYTES expects 2 arguments: name and length");
        }
        const std::string& name = parts[1];
        const std::string& len_str = parts[2];

        size_t n = 0;
        if (len_str == "REST") {
          n = data_size - data_pos;
        } else {
          n = static_cast<size_t>(std::stoul(len_str));
        }

        if (data_pos + n > data_size) {
          // Not enough data; truncate or just break.
          n = data_size - data_pos;
        }

        SegmentInfo seg;
        seg.offset = data_pos;
        seg.length = n;
        segments[name] = seg;

        // Insert raw bytes into output
        for (size_t k = 0; k < n; ++k) {
          out.push_back(static_cast<char>(data[data_pos + k]));
        }
        data_pos += n;

      } else if (op == "LEN") {
        // {{LEN:name}}
        if (parts.size() != 2) {
          throw std::runtime_error("LEN expects 1 argument: name");
        }
        const std::string& name = parts[1];
        auto it = segments.find(name);
        if (it == segments.end()) {
          // Unknown segment; treat length as 0 or error.
          // Here we choose "0" to keep going.
          out += "0";
        } else {
          out += std::to_string(it->second.length);
        }

      } else {
        // Unknown op -> you can either error or just copy it literally.
        // For now, just ignore the token.
        // Alternatively: out += "{{" + inside + "}}";
      }
    } else {
      out.push_back(tmpl[i]);
      ++i;
    }
  }

  return out;
}

#ifdef TEST

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
  /Decode [ 0 1 0 1 {{BYTES:decode_floats:24}} ]
  /Function 6 0 R
  /Length {{LEN:mesh_stream}}
>>
stream
{{BYTES:mesh_stream:REST}}
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

// Testing

unsigned char buf[100000]; // 100k input buffer

int main(int argc, char** argv) {
  int len = read(0, buf, sizeof(buf)); // Read from stdin...
  std::cout << ApplyPdfTemplate(kShadingTemplate, buf, len);
  return 0;
}

#endif