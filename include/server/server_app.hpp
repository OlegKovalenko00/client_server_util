#pragma once

#include "server/server_options.hpp"

namespace malware_scan::server {

class ServerApp {
public:
  explicit ServerApp(ServerOptions options);

  int run() const;

private:
  ServerOptions options_;
};

} // namespace malware_scan::server
