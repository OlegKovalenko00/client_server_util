#include "common/scan_statistics.hpp"

#include <charconv>
#include <sstream>
#include <stdexcept>
#include <string>

namespace malware_scan::common {
namespace {

std::uint64_t parse_unsigned(std::string_view raw) {
  std::uint64_t value = 0;
  const auto *begin = raw.data();
  const auto *end = raw.data() + raw.size();

  const auto [ptr, error] = std::from_chars(begin, end, value);
  if (error != std::errc{} || ptr != end) {
    throw std::runtime_error("invalid unsigned integer: " + std::string(raw));
  }

  return value;
}

} // namespace

std::string serialize_statistics(const ScanStatisticsSnapshot &snapshot) {
  std::ostringstream out;
  out << "scanned_files=" << snapshot.scanned_files << '\n';

  for (const auto &[pattern_id, count] : snapshot.pattern_hits) {
    out << "pattern:" << pattern_id << '=' << count << '\n';
  }

  return out.str();
}

ScanStatisticsSnapshot parse_statistics(std::string_view serialized) {
  ScanStatisticsSnapshot snapshot;

  while (!serialized.empty()) {
    const auto line_end = serialized.find('\n');
    const std::string_view line = line_end == std::string_view::npos
                                      ? serialized
                                      : serialized.substr(0, line_end);

    if (!line.empty()) {
      if (line.rfind("scanned_files=", 0) == 0) {
        snapshot.scanned_files = parse_unsigned(line.substr(14));
      } else if (line.rfind("pattern:", 0) == 0) {
        const auto separator = line.find('=');
        if (separator == std::string_view::npos || separator <= 8) {
          throw std::runtime_error("invalid pattern statistics line");
        }

        const auto pattern_id = std::string(line.substr(8, separator - 8));
        snapshot.pattern_hits.emplace(
            pattern_id, parse_unsigned(line.substr(separator + 1)));
      } else {
        throw std::runtime_error("unknown statistics line: " +
                                 std::string(line));
      }
    }

    if (line_end == std::string_view::npos) {
      break;
    }

    serialized.remove_prefix(line_end + 1);
  }

  return snapshot;
}

std::string
format_statistics_for_console(const ScanStatisticsSnapshot &snapshot) {
  std::ostringstream out;
  out << "Scanned files: " << snapshot.scanned_files << '\n';
  out << "Detected patterns:";

  if (snapshot.pattern_hits.empty()) {
    out << " none";
    return out.str();
  }

  for (const auto &[pattern_id, count] : snapshot.pattern_hits) {
    out << "\n- " << pattern_id << ": " << count;
  }

  return out.str();
}

} // namespace malware_scan::common
