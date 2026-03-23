#pragma once

#include "stats_cli/stats_client_options.hpp"

namespace malware_scan::stats_cli {

class StatsClientApp {
public:
  explicit StatsClientApp(StatsClientOptions options);

  int run() const;

private:
  StatsClientOptions options_;
};

} // namespace malware_scan::stats_cli
