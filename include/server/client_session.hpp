#pragma once

#include "server/client_worker.hpp"

namespace malware_scan::server {

int serve_single_client(int client_fd, const ClientWorker &worker,
                        int stats_write_fd);

}
