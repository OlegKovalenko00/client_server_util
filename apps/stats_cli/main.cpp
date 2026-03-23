#include <cstdlib>
#include <exception>
#include <iostream>

#include "stats_cli/stats_client_app.hpp"
#include "stats_cli/stats_client_options.hpp"

int main(int argc, char **argv) {
  try {
    const auto options =
        malware_scan::stats_cli::StatsClientOptions::parse(argc, argv);
    return malware_scan::stats_cli::StatsClientApp{options}.run();
  } catch (const std::exception &error) {
    std::cerr << "scan_stats error: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
