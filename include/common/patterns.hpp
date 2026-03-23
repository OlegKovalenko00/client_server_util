#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace malware_scan::common {

struct PatternDefinition {
  std::string id;
  std::string needle;
};

struct PatternConfig {
  std::vector<PatternDefinition> patterns;
};

struct PatternMatch {
  std::string pattern_id;
  std::size_t count = 0;
};

struct ScanResult {
  bool has_threats = false;
  std::vector<PatternMatch> matches;
};

} // namespace malware_scan::common
