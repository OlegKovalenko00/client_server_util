#include "client/client_app.hpp"

#include <iostream>

#include "client/tcp_client.hpp"
#include "common/file_utils.hpp"
#include "common/protocol.hpp"

namespace malware_scan::client {

ClientApp::ClientApp(ClientOptions options) : options_(std::move(options)) {}

int ClientApp::run() const {
  const std::string content = common::read_text_file(options_.file_path);

  common::FileScanRequest request;
  request.file_name = options_.file_path.filename().string();
  request.content = content;

  const ScanClient client{options_.port};
  const auto response = client.submit(request);

  std::cout << common::format_scan_response(response) << '\n';
  return 0;
}

} // namespace malware_scan::client
