# 3.28 for EXCLUDE_FROM_ALL in FetchContent_Declare and a settled FetchContent
# extract behaviour.
cmake_minimum_required(VERSION 3.28)

project(procpcap VERSION 1.0.0 LANGUAGES C CXX)

if(NOT MSVC)
    message(FATAL_ERROR "procpcap uses WinDivert and the Win32 API, and builds with MSVC only.")
endif()

get_property(_pp_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _pp_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT, so procpcap.exe runs on a clean Windows install with no VC++
# redistributable. WinDivert.dll still ships beside it.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(PROCPCAP_BUILD_TESTS "Build the unit tests" ON)
option(PROCPCAP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PROCPCAP_ARCH x64)
else()
    set(PROCPCAP_ARCH x86)
endif()

include(FetchContent)

# ---------------------------------------------------------------------------
# WinDivert: the signed user-mode library and kernel driver that delivers the
# packets. Fetched as the official release zip and used unmodified. Dual
# LGPLv3 / GPLv2 licensed; see THIRD_PARTY_NOTICES.md.
# ---------------------------------------------------------------------------
FetchContent_Declare(
    windivert
    URL https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
    URL_HASH SHA256=63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(windivert)

# The zip may or may not keep its single top-level folder after extraction, so
# find the layout rather than assume it.
if(EXISTS ${windivert_SOURCE_DIR}/include/windivert.h)
    set(WINDIVERT_ROOT ${windivert_SOURCE_DIR})
elseif(EXISTS ${windivert_SOURCE_DIR}/WinDivert-2.2.2-A/include/windivert.h)
    set(WINDIVERT_ROOT ${windivert_SOURCE_DIR}/WinDivert-2.2.2-A)
else()
    message(FATAL_ERROR "Could not find windivert.h under ${windivert_SOURCE_DIR}")
endif()

set(WINDIVERT_INCLUDE ${WINDIVERT_ROOT}/include)
set(WINDIVERT_LIB ${WINDIVERT_ROOT}/${PROCPCAP_ARCH}/WinDivert.lib)
set(WINDIVERT_DLL ${WINDIVERT_ROOT}/${PROCPCAP_ARCH}/WinDivert.dll)
if(PROCPCAP_ARCH STREQUAL "x64")
    set(WINDIVERT_SYS ${WINDIVERT_ROOT}/${PROCPCAP_ARCH}/WinDivert64.sys)
else()
    set(WINDIVERT_SYS ${WINDIVERT_ROOT}/${PROCPCAP_ARCH}/WinDivert32.sys)
endif()

add_library(windivert INTERFACE)
# SYSTEM so /W4 /WX applies to our code and not WinDivert's header.
target_include_directories(windivert SYSTEM INTERFACE ${WINDIVERT_INCLUDE})
target_link_libraries(windivert INTERFACE ${WINDIVERT_LIB})

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------
add_library(procpcap_warnings INTERFACE)
target_compile_options(procpcap_warnings INTERFACE /W4 /permissive- /Zc:__cplusplus /utf-8)
if(PROCPCAP_WARNINGS_AS_ERRORS)
    target_compile_options(procpcap_warnings INTERFACE /WX)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/Version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/Version.h
    @ONLY
)

# ---------------------------------------------------------------------------
# procpcap_core: the pcapng writer, flow table, IP parser, entropy, stats and
# CLI. No WinDivert or Win32 dependency, so the tests link it directly.
# ---------------------------------------------------------------------------
add_library(procpcap_core STATIC
    src/core/Cli.cpp
    src/core/Entropy.cpp
    src/core/FlowTable.cpp
    src/core/IpPacket.cpp
    src/core/PcapNg.cpp
    src/core/Stats.cpp
)
target_compile_features(procpcap_core PUBLIC cxx_std_20)
target_include_directories(procpcap_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(procpcap_core PRIVATE procpcap_warnings)

# ---------------------------------------------------------------------------
# procpcap.exe: the core plus the WinDivert-facing app layer.
# ---------------------------------------------------------------------------
add_executable(procpcap
    src/app/main.cpp
    src/app/Capture.cpp
    src/app/FlowSeed.cpp
    src/app/ProcessInfo.cpp
    resources/procpcap.rc
)
target_link_libraries(procpcap PRIVATE procpcap_core procpcap_warnings windivert iphlpapi ws2_32 shell32)
# _CRT_SECURE_NO_WARNINGS: this code uses _wfopen and the narrow C file API on
# purpose, checking every result, rather than the _s variants.
target_compile_definitions(procpcap PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
set_source_files_properties(resources/procpcap.rc PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

# Put WinDivert.dll and the driver next to procpcap.exe so it can be run from the
# build tree without copying files by hand.
add_custom_command(TARGET procpcap POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${WINDIVERT_DLL} $<TARGET_FILE_DIR:procpcap>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${WINDIVERT_SYS} $<TARGET_FILE_DIR:procpcap>
    VERBATIM
)

# ---------------------------------------------------------------------------
# synth_pcapng: a development aid that emits a synthetic capture with the writer,
# no driver needed. Not installed in the release zip.
# ---------------------------------------------------------------------------
add_executable(procpcap-synth tools/synth_pcapng.cpp)
target_include_directories(procpcap-synth PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_compile_definitions(procpcap-synth PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(procpcap-synth PRIVATE procpcap_core procpcap_warnings)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(PROCPCAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Package: procpcap.exe, the WinDivert runtime files, the docs and both
# licences, in one zip.
# ---------------------------------------------------------------------------
install(TARGETS procpcap RUNTIME DESTINATION procpcap)
install(FILES ${WINDIVERT_DLL} ${WINDIVERT_SYS} DESTINATION procpcap)
install(FILES ${WINDIVERT_ROOT}/LICENSE DESTINATION procpcap RENAME WinDivert-LICENSE.txt)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION procpcap
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/examples/ DESTINATION procpcap/examples)

set(CPACK_PACKAGE_NAME "procpcap")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "procpcap-v${PROJECT_VERSION}-${PROCPCAP_ARCH}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Per-process packet capture on Windows")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
