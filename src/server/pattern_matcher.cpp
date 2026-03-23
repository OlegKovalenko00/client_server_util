#include "server/pattern_matcher.hpp"

namespace malware_scan::server {
namespace {

std::size_t count_occurrences(std::string_view haystack,
                              std::string_view needle) {
  std::size_t count = 0;
  std::size_t offset = 0;

  while (offset < haystack.size()) {
    const auto match_pos = haystack.find(needle, offset);
    if (match_pos == std::string_view::npos) {
      break;
    }

    ++count;
    offset = match_pos + needle.size();
  }

  return count;
}

} // namespace

PatternMatcher::PatternMatcher(common::PatternConfig config)
    : config_(std::move(config)) {}

common::ScanResult PatternMatcher::scan(const std::string_view content) const {
  common::ScanResult result;

  for (const auto &pattern : config_.patterns) {
    const auto occurrences = count_occurrences(content, pattern.needle);
    if (occurrences == 0) {
      continue;
    }

    result.matches.push_back(common::PatternMatch{pattern.id, occurrences});
  }

  result.has_threats = !result.matches.empty();
  return result;
}

} // namespace malware_scan::server
