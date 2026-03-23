cmake_minimum_required(VERSION 3.20)

project(client_server_util LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(scan_common
    src/common/wire_protocol.cpp
    src/common/socket_io.cpp
    src/common/cli_utils.cpp
    src/common/file_utils.cpp
    src/common/protocol.cpp
    src/common/scan_statistics.cpp
)
target_include_directories(scan_common PUBLIC include)

add_library(scan_client_lib
    src/client/client_app.cpp
    src/client/client_options.cpp
    src/client/tcp_client.cpp
)
target_include_directories(scan_client_lib PUBLIC include)
target_link_libraries(scan_client_lib PUBLIC scan_common)

add_library(scan_server_lib
    src/server/stats_fifo_service.cpp
    src/server/stats_pipe_protocol.cpp
    src/server/client_session.cpp
    src/server/client_worker.cpp
    src/server/config_loader.cpp
    src/server/pattern_matcher.cpp
    src/server/server_app.cpp
    src/server/server_options.cpp
    src/server/signal_state.cpp
    src/server/stats_registry.cpp
)
target_include_directories(scan_server_lib PUBLIC include)
target_link_libraries(scan_server_lib PUBLIC scan_common)

add_library(scan_stats_cli_lib
    src/stats_cli/fifo_stats_client.cpp
    src/stats_cli/stats_client_app.cpp
    src/stats_cli/stats_client_options.cpp
)
target_include_directories(scan_stats_cli_lib PUBLIC include)
target_link_libraries(scan_stats_cli_lib PUBLIC scan_common)

add_executable(scan_client apps/client/main.cpp)
target_link_libraries(scan_client PRIVATE scan_client_lib)

add_executable(scan_server apps/server/main.cpp)
target_link_libraries(scan_server PRIVATE scan_server_lib)

add_executable(scan_stats apps/stats_cli/main.cpp)
target_link_libraries(scan_stats PRIVATE scan_stats_cli_lib)

include(CTest)
if(BUILD_TESTING)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTEST REQUIRED IMPORTED_TARGET gtest_main)
    include(GoogleTest)

    add_executable(scan_unit_tests
        tests/pattern_matcher_smoke.cpp
        tests/wire_protocol_smoke.cpp
        tests/stats_pipe_protocol_smoke.cpp
        tests/client_session_smoke.cpp
    )
    target_link_libraries(scan_unit_tests PRIVATE scan_server_lib PkgConfig::GTEST)
    gtest_discover_tests(scan_unit_tests DISCOVERY_TIMEOUT 30)

    add_test(
        NAME end_to_end_smoke
        COMMAND
            /bin/bash
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/end_to_end_smoke.sh
            $<TARGET_FILE:scan_server>
            $<TARGET_FILE:scan_client>
            $<TARGET_FILE:scan_stats>
            ${CMAKE_CURRENT_SOURCE_DIR}/configs/patterns.conf.example
    )
    set_tests_properties(end_to_end_smoke PROPERTIES TIMEOUT 20)
endif()
