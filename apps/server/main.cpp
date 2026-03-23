#include <cstdlib>
#include <exception>
#include <iostream>

#include "server/server_app.hpp"
#include "server/server_options.hpp"

int main(int argc, char **argv) {
  try {
    const auto options = malware_scan::server::ServerOptions::parse(argc, argv);
    return malware_scan::server::ServerApp{options}.run();
  } catch (const std::exception &error) {
    std::cerr << "scan_server error: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
