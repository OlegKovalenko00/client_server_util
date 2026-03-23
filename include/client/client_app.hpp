#pragma once

#include "client/client_options.hpp"

namespace malware_scan::client {

class ClientApp {
public:
  explicit ClientApp(ClientOptions options);

  int run() const;

private:
  ClientOptions options_;
};

} // namespace malware_scan::client
