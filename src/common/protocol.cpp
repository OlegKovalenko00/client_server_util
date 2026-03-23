#include "common/protocol.hpp"

#include <sstream>

namespace malware_scan::common {

std::string format_scan_response(const FileScanResponse &response) {
  std::ostringstream out;
  out << response.summary;

  if (!response.result.has_threats) {
    return out.str();
  }

  out << "\nMatched patterns:";
  for (const auto &match : response.result.matches) {
    out << "\n- " << match.pattern_id << ": " << match.count;
  }

  return out.str();
}

} // namespace malware_scan::common
