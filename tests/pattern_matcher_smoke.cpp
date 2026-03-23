#include <gtest/gtest.h>

#include "common/protocol.hpp"
#include "common/scan_statistics.hpp"
#include "server/client_worker.hpp"
#include "server/pattern_matcher.hpp"
#include "server/stats_registry.hpp"

TEST(PatternMatcherSmoke, WorkerAndStatsSerializationStayConsistent) {
  using namespace malware_scan;

  common::PatternConfig config;
  config.patterns.push_back(common::PatternDefinition{"eicar", "EICAR"});
  config.patterns.push_back(
      common::PatternDefinition{"shell_spawn", "/bin/sh"});

  const server::PatternMatcher matcher{config};
  const server::ClientWorker worker{matcher};

  common::FileScanRequest request;
  request.file_name = "sample.txt";
  request.content = "prefix EICAR middle EICAR tail /bin/sh";

  const auto response = worker.process(request);

  EXPECT_TRUE(response.result.has_threats);
  ASSERT_EQ(response.result.matches.size(), 2U);

  server::StatsRegistry registry;
  registry.record_scan(response.result);

  const auto snapshot = registry.snapshot();
  EXPECT_EQ(snapshot.scanned_files, 1U);
  EXPECT_EQ(snapshot.pattern_hits.at("eicar"), 2U);
  EXPECT_EQ(snapshot.pattern_hits.at("shell_spawn"), 1U);

  const auto serialized = common::serialize_statistics(snapshot);
  const auto parsed = common::parse_statistics(serialized);

  EXPECT_EQ(parsed.scanned_files, snapshot.scanned_files);
  EXPECT_EQ(parsed.pattern_hits, snapshot.pattern_hits);
}
