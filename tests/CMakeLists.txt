include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

add_executable(procpcap_tests
    test_cli.cpp
    test_entropy.cpp
    test_flowtable.cpp
    test_ippacket.cpp
    test_pcapng.cpp
    test_stats.cpp
)
target_include_directories(procpcap_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(procpcap_tests PRIVATE procpcap_core procpcap_warnings Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(procpcap_tests)
