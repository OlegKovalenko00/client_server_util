#pragma once

#include <filesystem>

#include "common/scan_statistics.hpp"

namespace malware_scan::stats_cli {

class FifoStatsClient {
public:
  FifoStatsClient(std::filesystem::path request_fifo,
                  std::filesystem::path response_fifo);

  common::ScanStatisticsSnapshot fetch() const;

private:
  std::filesystem::path request_fifo_;
  std::filesystem::path response_fifo_;
};

} // namespace malware_scan::stats_cli
