#include "common/wire_protocol.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include "common/socket_io.hpp"

namespace malware_scan::common {
void write_uint8(int fd, std::uint8_t value) {
  write_exact(fd, &value, sizeof(value));
}
std::uint8_t read_uint8(int fd) {
  std::uint8_t value = 0;
  read_exact(fd, &value, sizeof(value));
  return value;
}
void write_uint32(int fd, std::uint32_t value) {
  std::uint8_t bytes[4];

  bytes[0] = static_cast<std::uint8_t>(((value >> 24) & 0xFF));
  bytes[1] = static_cast<std::uint8_t>(((value >> 16) & 0xFF));
  bytes[2] = static_cast<std::uint8_t>(((value >> 8) & 0xFF));
  bytes[3] = static_cast<std::uint8_t>(((value) & 0xFF));

  write_exact(fd, &bytes, sizeof(bytes));
}
std::uint32_t read_uint32(int fd) {
  std::uint8_t bytes[4];
  read_exact(fd, &bytes, sizeof(bytes));

  std::uint32_t value = 0;
  value |= static_cast<std::uint32_t>(bytes[0] << 24);
  value |= static_cast<std::uint32_t>(bytes[1] << 16);
  value |= static_cast<std::uint32_t>(bytes[2] << 8);
  value |= static_cast<std::uint32_t>(bytes[3]);

  return value;
}
void write_uint64(int fd, std::uint64_t value) {
  std::uint8_t bytes[8];

  bytes[0] = static_cast<std::uint8_t>((value >> 56) & 0xFF);
  bytes[1] = static_cast<std::uint8_t>((value >> 48) & 0xFF);
  bytes[2] = static_cast<std::uint8_t>((value >> 40) & 0xFF);
  bytes[3] = static_cast<std::uint8_t>((value >> 32) & 0xFF);
  bytes[4] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
  bytes[5] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
  bytes[6] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
  bytes[7] = static_cast<std::uint8_t>(value & 0xFF);

  write_exact(fd, bytes, sizeof(bytes));
}

std::uint64_t read_uint64(int fd) {
  std::uint8_t bytes[8];
  read_exact(fd, bytes, sizeof(bytes));

  std::uint64_t value = 0;
  value |= static_cast<std::uint64_t>(bytes[0]) << 56;
  value |= static_cast<std::uint64_t>(bytes[1]) << 48;
  value |= static_cast<std::uint64_t>(bytes[2]) << 40;
  value |= static_cast<std::uint64_t>(bytes[3]) << 32;
  value |= static_cast<std::uint64_t>(bytes[4]) << 24;
  value |= static_cast<std::uint64_t>(bytes[5]) << 16;
  value |= static_cast<std::uint64_t>(bytes[6]) << 8;
  value |= static_cast<std::uint64_t>(bytes[7]);

  return value;
}

void write_string32(int fd, const std::string &value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::runtime_error("string is too large to seriealise");
  }
  write_uint32(fd, static_cast<std::uint32_t>(value.size()));

  if (!value.empty()) {
    write_exact(fd, value.data(), value.size());
  }
}
std::string read_string32(int fd, std::uint32_t max_size) {
  const std::uint32_t size = read_uint32(fd);

  if (size > max_size) {
    throw std::runtime_error("incoming string more than limits");
  }

  std::string value(size, '\0');

  if (size > 0) {
    read_exact(fd, value.data(), value.size());
  }

  return value;
}
void write_blob64(int fd, const std::string &value) {
  if (value.size() > std::numeric_limits<std::uint64_t>::max()) {
    throw std::runtime_error("blob is too large to serialize");
  }

  write_uint64(fd, static_cast<std::uint64_t>(value.size()));

  if (!value.empty()) {
    write_exact(fd, value.data(), value.size());
  }
}

std::string read_blob64(int fd, std::uint64_t max_size) {
  const std::uint64_t size = read_uint64(fd);

  if (size > max_size) {
    throw std::runtime_error("incoming blob more than limit");
  }

  if (size >
      static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    throw std::runtime_error(
        "incoming blob does not fit into memory size type");
  }

  std::string value(static_cast<std::size_t>(size), '\0');

  if (size > 0) {
    read_exact(fd, value.data(), value.size());
  }

  return value;
}

void write_request(int fd, const FileScanRequest &request) {
  if (request.file_name.size() > k_max_file_name_size) {
    throw std::runtime_error("file name is too long");
  }
  if (request.content.size() > k_max_content_size) {
    throw std::runtime_error("file content is too large");
  }

  write_string32(fd, request.file_name);
  write_blob64(fd, request.content);
}

FileScanRequest read_request(int fd) {
  FileScanRequest request;
  request.file_name = read_string32(fd, k_max_file_name_size);
  request.content = read_blob64(fd, k_max_content_size);
  return request;
}
void write_response(int fd, const FileScanResponse &response) {
  write_uint8(fd, response.result.has_threats ? 1 : 0);

  if (response.result.matches.size() > k_max_matches_count) {
    throw std::runtime_error("too many matches in response");
  }
  write_uint32(fd, static_cast<std::uint32_t>(response.result.matches.size()));

  for (const auto &match : response.result.matches) {
    if (match.pattern_id.size() > k_max_pattern_id_size) {
      throw std::runtime_error("pattern id is too large");
    }

    write_string32(fd, match.pattern_id);
    write_uint64(fd, static_cast<std::uint64_t>(match.count));
  }

  if (response.summary.size() > k_max_summary_size) {
    throw std::runtime_error("summary is too large");
  }

  write_string32(fd, response.summary);
}
FileScanResponse read_response(int fd) {
  FileScanResponse response;

  const std::uint8_t has_threats = read_uint8(fd);
  if (has_threats != 0 && has_threats != 1) {
    throw std::runtime_error("invalid has_threats flag");
  }
  response.result.has_threats = (has_threats == 1);

  const std::uint32_t matches_count = read_uint32(fd);
  if (matches_count > k_max_matches_count) {
    throw std::runtime_error("incoming matches count exceeds limit");
  }

  response.result.matches.reserve(matches_count);

  for (std::uint32_t i = 0; i < matches_count; ++i) {
    PatternMatch match;
    match.pattern_id = read_string32(fd, k_max_pattern_id_size);

    const std::uint64_t raw_count = read_uint64(fd);
    if (raw_count >
        static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
      throw std::runtime_error("pattern match count does not fit into size_t");
    }

    match.count = static_cast<std::size_t>(raw_count);
    response.result.matches.push_back(match);
  }

  response.summary = read_string32(fd, k_max_summary_size);

  return response;
}
} // namespace malware_scan::common
