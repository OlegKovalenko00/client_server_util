#pragma once

#include <cstdint>
#include <string>

#include "common/protocol.hpp"

namespace malware_scan::common {
inline constexpr std::uint32_t k_max_file_name_size = 1024;
inline constexpr std::uint32_t k_max_pattern_id_size = 256;
inline constexpr std::uint32_t k_max_summary_size = 4096;
inline constexpr std::uint32_t k_max_matches_count = 1024;
inline constexpr std::uint64_t k_max_content_size = 16ULL * 1024 * 1024;

void write_uint8(int fd, std::uint8_t value);
std::uint8_t read_uint8(int fd);
void write_uint32(int fd, std::uint32_t value);
std::uint32_t read_uint32(int fd);
void write_uint64(int fd, std::uint64_t value);
std::uint64_t read_uint64(int fd);

void write_string32(int fd, const std::string &value);
std::string read_string32(int fd, std::uint32_t max_size);
void write_blob64(int fd, const std::string &value);
std::string read_blob64(int fd, std::uint64_t max_size);

void write_request(int fd, const FileScanRequest &request);
FileScanRequest read_request(int fd);
void write_response(int fd, const FileScanResponse &response);
FileScanResponse read_response(int fd);

} // namespace malware_scan::common