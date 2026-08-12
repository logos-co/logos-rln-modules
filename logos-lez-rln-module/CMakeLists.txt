cmake_minimum_required(VERSION 3.14)
project(LogosLezRlnModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

logos_module(
    NAME liblogos_lez_rln_module
)

# ── Rust static library ──────────────────────────────────────────────────────
# The flake's preConfigure stages libliblogos_lez_rln_module.a into lib/; the
# cargo target dir is also searched for convenience outside Nix.
find_library(LIBLOGOS_RLN_MODULE_RUST
    NAMES libliblogos_lez_rln_module.a liblogos_lez_rln_module
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/rust-lib/target/release
        ${CMAKE_CURRENT_SOURCE_DIR}/rust-lib/target/debug
    NO_DEFAULT_PATH
)

if(NOT LIBLOGOS_RLN_MODULE_RUST)
    message(FATAL_ERROR
        "Rust static library (libliblogos_lez_rln_module.a) not found in ${CMAKE_CURRENT_SOURCE_DIR}/lib. "
        "Ensure the preConfigure hook staged the buildRustPackage output."
    )
endif()

message(STATUS "Found liblogos_lez_rln_module Rust static library: ${LIBLOGOS_RLN_MODULE_RUST}")

# The Rust archive's lp_* undefineds resolve against logos-protocol; keep the
# protocol target after the archive so single-pass linkers (GNU ld) see it
# later on the line.
target_link_libraries(liblogos_lez_rln_module_module_plugin PRIVATE
    ${LIBLOGOS_RLN_MODULE_RUST}
    logos-protocol::logos_protocol
)

if(APPLE)
    target_link_libraries(liblogos_lez_rln_module_module_plugin PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
else()
    target_link_libraries(liblogos_lez_rln_module_module_plugin PRIVATE pthread dl)
endif()
