#include <cstdlib>
#include <exception>
#include <iostream>

#include "client/client_app.hpp"
#include "client/client_options.hpp"

int main(int argc, char **argv) {
  try {
    const auto options = malware_scan::client::ClientOptions::parse(argc, argv);
    return malware_scan::client::ClientApp{options}.run();
  } catch (const std::exception &error) {
    std::cerr << "scan_client error: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
