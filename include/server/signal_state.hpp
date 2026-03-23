#pragma once

namespace malware_scan::server {

class SignalState {
public:
  static void install();
  static bool stop_requested();

private:
  static void handle_signal(int signal_number);
};

} // namespace malware_scan::server
