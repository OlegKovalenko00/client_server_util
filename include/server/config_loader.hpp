#pragma once

#include <filesystem>

#include "common/patterns.hpp"

namespace malware_scan::server {

class PatternConfigLoader {
public:
  common::PatternConfig load(const std::filesystem::path &config_path) const;
};

} // namespace malware_scan::server
