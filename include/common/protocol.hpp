#pragma once

#include <string>

#include "common/patterns.hpp"

namespace malware_scan::common {
struct FileScanRequest {
  std::string file_name;
  std::string content;
};

struct FileScanResponse {
  ScanResult result;
  std::string summary;
};

std::string format_scan_response(const FileScanResponse &response);

} // namespace malware_scan::common
