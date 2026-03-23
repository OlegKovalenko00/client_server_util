#pragma once

#include <string_view>

#include "common/patterns.hpp"

namespace malware_scan::server {

class PatternMatcher {
public:
  explicit PatternMatcher(common::PatternConfig config);

  common::ScanResult scan(std::string_view content) const;

private:
  common::PatternConfig config_;
};

} // namespace malware_scan::server
