#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <iostream>
#include <unistd.h>

// -------- Helpers --------

static std::string Trim(const std::string& s) {
  size_t a = 0;
  while (a < s.size() && std::isspace((unsigned char)s[a])) a++;
  size_t b = s.size();
  while (b > a && std::isspace((unsigned char)s[b-1])) b--;
  return s.substr(a, b - a);
}

static std::vector<std::string> Split(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == delim) { out.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  out.push_back(cur);
  return out;
}

// Convert bytes to float32 (big endian)
static float ReadBEFloat32(const uint8_t* p) {
  uint32_t v = (uint32_t(p[0]) << 24) |
               (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) << 8 ) |
               (uint32_t(p[3]));
  float f;
  memcpy(&f, &v, sizeof(float));
  return f;
}

static uint32_t ReadBEU32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) |
         (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8 ) |
         (uint32_t(p[3]));
}

static int32_t ReadBEI32(const uint8_t* p) {
  return int32_t((uint32_t(p[0]) << 24) |
                 (uint32_t(p[1]) << 16) |
                 (uint32_t(p[2]) << 8 ) |
                 (uint32_t(p[3])));
}

static std::string BytesToHex(const uint8_t* p, size_t n) {
  std::ostringstream oss;
  oss << "<";
  for (size_t i = 0; i < n; i++)
    oss << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(p[i]);
  oss << ">";
  return oss.str();
}

// -------- Main structure --------

struct SegmentInfo {
  size_t offset = 0;
  size_t length = 0;
};

std::string ApplyPdfTemplate(const std::string& tmpl,
                             const uint8_t* data,
                             size_t data_size)
{
  std::unordered_map<std::string, SegmentInfo> segments;
  size_t data_pos = 0;

  std::string out;
  out.reserve(tmpl.size() + 32);

  size_t i = 0;
  while (i < tmpl.size()) {

    // Look for {{ ... }}
    if (i+1 < tmpl.size() && tmpl[i] == '{' && tmpl[i+1] == '{') {
      size_t end = tmpl.find("}}", i+2);
      if (end == std::string::npos)
        throw std::runtime_error("Unterminated {{ }} template");

      std::string inside = Trim(tmpl.substr(i+2, end-(i+2)));
      i = end + 2;

      if (inside.empty()) continue;

      // Parse OP:arg1:arg2
      auto parts = Split(inside, ':');
      for (auto& p : parts) p = Trim(p);

      const std::string& op = parts[0];

      // ---------- BYTES ----------
      if (op == "BYTES") {
        if (parts.size() != 3)
          throw std::runtime_error("BYTES:name:N expected");

        std::string name = parts[1];
        size_t n = std::stoul(parts[2]);

        if (data_pos + n > data_size)
          n = data_size - data_pos;

        segments[name] = {data_pos, n};

        out.append((const char*)data + data_pos, n);
        data_pos += n;
      }

      // ---------- HEX ----------
      else if (op == "HEX") {
        if (parts.size() != 3)
          throw std::runtime_error("HEX:name:N expected");

        std::string name = parts[1];
        size_t n = std::stoul(parts[2]);

        if (data_pos + n > data_size)
          n = data_size - data_pos;

        segments[name] = {data_pos, n};

        out += BytesToHex(data + data_pos, n);
        data_pos += n;
      }

      // ---------- INT32BE ----------
      else if (op == "INT32BE") {
        if (parts.size() != 2)
          throw std::runtime_error("INT32BE:name expected");

        std::string name = parts[1];

        if (data_pos + 4 > data_size)
          break;

        int32_t v = ReadBEI32(data + data_pos);

        segments[name] = {data_pos, 4};
        data_pos += 4;

        out += std::to_string(v);
      }

      // ---------- UINT32BE ----------
      else if (op == "UINT32BE") {
        if (parts.size() != 2)
          throw std::runtime_error("UINT32BE:name expected");

        std::string name = parts[1];

        if (data_pos + 4 > data_size)
          break;

        uint32_t v = ReadBEU32(data + data_pos);

        segments[name] = {data_pos, 4};
        data_pos += 4;

        out += std::to_string(v);
      }

      // ---------- FLOAT32BE ----------
      else if (op == "FLOAT32BE") {
        if (parts.size() != 2)
          throw std::runtime_error("FLOAT32BE:name expected");

        std::string name = parts[1];

        if (data_pos + 4 > data_size)
          break;

        float f = ReadBEFloat32(data + data_pos);

        segments[name] = {data_pos, 4};
        data_pos += 4;

        // Print clean decimal
        std::ostringstream oss;
        oss << std::scientific << std::setprecision(9) << f;
        out += oss.str();
      }

      // ---------- LEN ----------
      else if (op == "LEN") {
        if (parts.size() != 2)
          throw std::runtime_error("LEN:name expected");

        std::string name = parts[1];
        auto it = segments.find(name);
        if (it == segments.end())
          out += "0";
        else
          out += std::to_string(it->second.length);
      }

      // ---------- UNKNOWN ----------
      else {
        // You can error or ignore; here we ignore.
      }

      continue;
    }

    // Regular character
    out.push_back(tmpl[i]);
    i++;
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
  /Decode [ 0 1 0 1 {{FLOAT32BE:decode_floats}} {{FLOAT32BE:decode_floats}} ]
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

// Testing

unsigned char buf[100000]; // 100k input buffer

int main(int argc, char** argv) {
  int len = read(0, buf, sizeof(buf)); // Read from stdin...
  std::cout << ApplyPdfTemplate(kShadingTemplate, buf, len);
  return 0;
}

#endif