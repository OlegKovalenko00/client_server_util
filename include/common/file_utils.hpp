#pragma once

#include <filesystem>
#include <string>

namespace malware_scan::common {

std::string read_text_file(const std::filesystem::path &path);

}
