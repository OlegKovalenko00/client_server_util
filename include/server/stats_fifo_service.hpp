#pragma once

#include <cstddef>
#include <filesystem>

#include "common/scan_statistics.hpp"

namespace malware_scan::server {

class StatsFifoService {
public:
  StatsFifoService(std::filesystem::path request_fifo,
                   std::filesystem::path response_fifo);

  void ensure_created() const;
  void remove_if_exists() const;

  int open_request_fd() const;
  std::size_t drain_request_markers(int request_fd) const;
  void send_snapshot(const common::ScanStatisticsSnapshot &snapshot) const;

private:
  std::filesystem::path request_fifo_;
  std::filesystem::path response_fifo_;
};

} // namespace malware_scan::server
