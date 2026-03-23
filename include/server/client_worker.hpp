#pragma once

#include "common/protocol.hpp"
#include "server/pattern_matcher.hpp"

namespace malware_scan::server {

class ClientWorker {
public:
  explicit ClientWorker(PatternMatcher matcher);

  common::FileScanResponse
  process(const common::FileScanRequest &request) const;

private:
  PatternMatcher matcher_;
};

} // namespace malware_scan::server
