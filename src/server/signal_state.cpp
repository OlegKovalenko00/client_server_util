#include "server/signal_state.hpp"

#include <atomic>
#include <csignal>
#include <stdexcept>

namespace malware_scan::server {
namespace {

std::atomic_bool g_stop_requested{false};

}

void SignalState::install() {
  struct sigaction action {};
  action.sa_handler = &SignalState::handle_signal;

  if (sigemptyset(&action.sa_mask) != 0) {
    throw std::runtime_error("sigemptyset failed");
  }

  if (sigaction(SIGINT, &action, nullptr) != 0) {
    throw std::runtime_error("failed to install SIGINT handler");
  }

  if (sigaction(SIGTERM, &action, nullptr) != 0) {
    throw std::runtime_error("failed to install SIGTERM handler");
  }
}

bool SignalState::stop_requested() { return g_stop_requested.load(); }

void SignalState::handle_signal(const int signal_number) {
  if (signal_number == SIGINT || signal_number == SIGTERM) {
    g_stop_requested.store(true);
  }
}

} // namespace malware_scan::server
