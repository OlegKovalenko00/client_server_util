#include "server/client_worker.hpp"

namespace malware_scan::server {

ClientWorker::ClientWorker(PatternMatcher matcher)
    : matcher_(std::move(matcher)) {}

common::FileScanResponse
ClientWorker::process(const common::FileScanRequest &request) const {
  auto result = matcher_.scan(request.content);

  common::FileScanResponse response;
  response.result = std::move(result);
  response.summary = response.result.has_threats
                         ? "Threats found in file: " + request.file_name
                         : "No threats found in file: " + request.file_name;

  return response;
}

} // namespace malware_scan::server
