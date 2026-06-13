cmake_minimum_required(VERSION 3.20)
project(argus C CXX)
include_directories(include)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies (via vcpkg)
find_package(cJSON CONFIG REQUIRED)
find_package(unofficial-libyara CONFIG)  # optional; enables YARA_AVAILABLE when installed

# Shared include path (events.h visible to both targets)
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)
include_directories(${DETOURS_INCLUDE_DIRS} ${DETOURS_INCLUDE_DIRS}/detours)

# ============================================================================
# argus_hook - Shared Library (DLL)
# ============================================================================
add_library(argus_hook SHARED
    src/hook_dll/dllmain.cpp
    src/hook_dll/hooks.c
    src/hook_dll/hooks.h
    src/hook_dll/event_queue.c
    src/hook_dll/event_queue.h
    src/hook_dll/ipc_client.c
    src/hook_dll/ipc_client.h
)

target_include_directories(argus_hook PRIVATE
    ${CMAKE_SOURCE_DIR}/src/hook_dll
)

# Link libraries for hook DLL
target_link_libraries(argus_hook PRIVATE cjson)

# Link Detours - check for vcpkg or local lib
if(EXISTS "${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx64.lib")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_libraries(argus_hook PRIVATE
            ${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx64.lib
        )
    else()
        target_link_libraries(argus_hook PRIVATE
            ${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx86.lib
        )
    endif()
else()
    # Try to find Detours via vcpkg
    find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
    find_library(DETOURS_LIBRARY detours REQUIRED)
    include_directories(${DETOURS_INCLUDE_DIRS})
    target_link_libraries(argus_hook PRIVATE cjson ${DETOURS_LIBRARY})
endif()

# ============================================================================
# argus_agent - Executable
# ============================================================================
add_executable(argus_agent
    src/agent/main.c
    src/agent/ipc_server.c
    src/agent/ipc_server.h
    src/agent/pesieve_server.c
    src/agent/pesieve_server.h
    src/agent/scanner.c
    src/agent/scanner.h
    src/agent/yara_scanner.c
    src/agent/yara_scanner.h
    src/agent/correlator.c
    src/agent/correlator.h
)

target_include_directories(argus_agent PRIVATE
    ${CMAKE_SOURCE_DIR}/src/agent
)

# Link libraries for agent
target_link_libraries(argus_agent PRIVATE
    cjson
    ws2_32
    winhttp
)

# Optional: Add YARA support if available
if(TARGET unofficial::libyara::libyara)
    target_compile_definitions(argus_agent PRIVATE YARA_AVAILABLE)
    target_link_libraries(argus_agent PRIVATE unofficial::libyara::libyara)
endif()

# ============================================================================
# injector - Classic DLL injector
# ============================================================================
add_executable(injector src/injector/main.c)

# ============================================================================
# test_target - End-to-end test harness (Trinity / EICAR)
# ============================================================================
add_executable(test_target src/test_target/main.c)
target_include_directories(test_target PRIVATE ${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# shellcode_runner - Metasploit calc.exe shellcode loader for Part 2 E2E test
# ============================================================================
add_executable(shellcode_runner src/shellcode_runner/main.c)

# ============================================================================
# dummy_malware - Synthetic RWX shellcode target for PE-Sieve E2E tests
# ============================================================================
add_executable(dummy_malware src/agent/dummy_malware.c)

# ============================================================================
# test_eq - EventQueue unit test
# ============================================================================
add_executable(test_eq
    exercises/test_eq_standalone.c
    src/hook_dll/event_queue.c
)
target_include_directories(test_eq PRIVATE
    ${CMAKE_SOURCE_DIR}/src/hook_dll
    ${CMAKE_SOURCE_DIR}/include
)

# Set output directories (all binaries go to build/bin/<config>/)
set_target_properties(argus_hook argus_agent injector test_target test_eq
                      dummy_malware shellcode_runner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Installation rules
install(TARGETS argus_hook argus_agent test_target shellcode_runner
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/argus
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# ============================================================================
# pe-sieve submodule - built as a static library
# pe-sieve's CMakeLists.txt uses CMAKE_SOURCE_DIR (not PROJECT_SOURCE_DIR) for
# the paramkit path, which breaks when consumed as a subdirectory. Override the
# cache variable here so it resolves relative to the submodule, not the root.
# ============================================================================
set(PESIEVE_BUILD_MODE "STATIC" CACHE STRING "" FORCE)
set(PESIEVE_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(PARAMKIT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/pe-sieve/paramkit/paramkit" CACHE PATH "" FORCE)
add_subdirectory(pe-sieve)

# ============================================================================
# argus_pesieve - Injected DLL that runs PE-Sieve in-process and reports
#                 findings back to argus_agent via \\.\pipe\argus-pesieve
# ============================================================================
add_library(argus_pesieve SHARED
    src/pesieve_dll/dllmain.cpp
    src/pesieve_dll/ownership.cpp
    src/pesieve_dll/patch_filter.cpp
    src/pesieve_dll/ipc.cpp
)

target_include_directories(argus_pesieve PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/pe-sieve/include
)

# PESIEVE_STATIC_LIB propagates transitively from the pe-sieve target (PUBLIC).
# libpeconv, sig_finder, and paramkit propagate as interface link deps of pe-sieve.
target_link_libraries(argus_pesieve PRIVATE
    pe-sieve
    cjson
    rpcrt4
    psapi
    ntdll
    shlwapi
    imagehlp
    dbghelp
)

set_target_properties(argus_pesieve PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# ============================================================================
# Copy the rules/ directory next to the agent after every build
# ============================================================================
add_custom_command(TARGET argus_agent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/rules
        $<TARGET_FILE_DIR:argus_agent>/rules
    COMMENT "Syncing rules/ to $<TARGET_FILE_DIR:argus_agent>/rules"
)