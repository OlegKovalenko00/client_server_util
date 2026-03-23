#include "common/file_utils.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace malware_scan::common {

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open file: " + path.string());
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

} // namespace malware_scan::common
