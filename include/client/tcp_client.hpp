#pragma once

#include <cstdint>

#include "common/protocol.hpp"

namespace malware_scan::client {

class ScanClient {
public:
  explicit ScanClient(std::uint16_t port);

  common::FileScanResponse submit(const common::FileScanRequest &request) const;

private:
  std::uint16_t port_;
};

} // namespace malware_scan::client
