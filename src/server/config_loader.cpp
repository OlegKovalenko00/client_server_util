#include "server/config_loader.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace malware_scan::server {
namespace {

std::string trim(std::string value) {
  const auto is_space = [](const unsigned char ch) {
    return std::isspace(ch) != 0;
  };

  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
                                          [&](const unsigned char ch) {
                                            return !is_space(ch);
                                          }));

  value.erase(
      std::find_if(value.rbegin(), value.rend(),
                   [&](const unsigned char ch) { return !is_space(ch); })
          .base(),
      value.end());

  return value;
}

} // namespace

common::PatternConfig
PatternConfigLoader::load(const std::filesystem::path &config_path) const {
  std::ifstream input(config_path);
  if (!input) {
    throw std::runtime_error("failed to open pattern config: " +
                             config_path.string());
  }

  common::PatternConfig config;
  std::unordered_set<std::string> ids;
  std::string line;
  std::size_t line_number = 0;

  while (std::getline(input, line)) {
    ++line_number;

    const auto trimmed = trim(line);
    if (trimmed.empty() || trimmed.front() == '#') {
      continue;
    }

    const auto separator = trimmed.find('=');
    if (separator == std::string::npos) {
      throw std::runtime_error("invalid pattern config line " +
                               std::to_string(line_number) + ": missing '='");
    }

    auto pattern_id = trim(trimmed.substr(0, separator));
    auto needle = trim(trimmed.substr(separator + 1));

    if (pattern_id.empty() || needle.empty()) {
      throw std::runtime_error("invalid pattern config line " +
                               std::to_string(line_number) +
                               ": empty id or value");
    }

    if (!ids.insert(pattern_id).second) {
      throw std::runtime_error("duplicate pattern id: " + pattern_id);
    }

    config.patterns.push_back(
        common::PatternDefinition{std::move(pattern_id), std::move(needle)});
  }

  if (config.patterns.empty()) {
    throw std::runtime_error("pattern config is empty");
  }

  return config;
}

} // namespace malware_scan::server
