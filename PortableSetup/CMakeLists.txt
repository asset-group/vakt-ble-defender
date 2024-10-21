cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_C_COMPILER "clang-15")
set(CMAKE_CXX_COMPILER "clang++-15")

project(
  vaktble
  LANGUAGES CXX C
  VERSION 1.0)

message(INFO "Current Generator: ${CMAKE_GENERATOR}")
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS 1
  CACHE INTERNAL "No dev warnings")

# ---------------- System Dependencies --------------------
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++2a" COMPILER_SUPPORTS_CXX20)

if(NOT COMPILER_SUPPORTS_CXX20)
  message(FATAL_ERROR "Compiler ${CC} does not support C++20")
endif()

# * pkg-config
find_program(PKG-CONFIG_EXIST "pkg-config" REQUIRED)

# * pthreads
find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

if(GLIB_FOUND)
  message("Found GLIB-2.0 library")
  message("LD Flags: ${GLIB_LDFLAGS}")
  message("C Flags: ${GLIB_CFLAGS}")
endif()

# ---------------- Configuration --------------------
# Options
set(CMAKE_BUILD_TYPE "RelWithDebInfo")
set(CMAKE_EXPORT_COMPILE_COMMANDS
  ON
  CACHE BOOL "Export compile_commands.json" FORCE)
set(ENABLE_EXPORTS ON)
set(FETCHCONTENT_QUIET FALSE)
option(FORCE_COLORED_OUTPUT
  "Always produce ANSI-colored output (GNU/Clang only)." TRUE)

if(${FORCE_COLORED_OUTPUT})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
  elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
  endif()
endif()

include(FetchContent)

# Configure Output folders
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Global compiler options
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  # set(COMMON_FLAGS
  #   "-fno-stack-protector -fpic -Wall -Wno-braced-scalar-init -Wno-unused-variable -Wno-reorder -flto=thin"
  # )
  set(COMMON_FLAGS
  "-fno-stack-protector -fpic -Wall -Wno-braced-scalar-init -Wno-unused-variable -Wno-reorder"
  )
else()
  set(COMMON_FLAGS
    "-fno-stack-protector -fpic -Wall -Wno-braced-scalar-init -Wno-unused-variable -Wno-reorder"
  )
endif()

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} ${COMMON_FLAGS})
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${COMMON_FLAGS})
set(CMAKE_PCH_INSTANTIATE_TEMPLATES ON)
set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)
set(CMAKE_BUILD_RPATH $ORIGIN bin)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so" ".a")

# Configure linker (enforce lld-15)
add_link_options("-fuse-ld=lld-15")

# Print some options
message(INFO "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(INFO "EXPORT_COMPILE_COMMANDS: ${EXPORT_COMPILE_COMMANDS}")

# ---------------- Includes --------------------
# Global Includes
include_directories(
  AFTER ${PROJECT_SOURCE_DIR}/ 
  ${PROJECT_SOURCE_DIR}/src/
  ${PROJECT_SOURCE_DIR}/libs/
  ${PROJECT_SOURCE_DIR}/libs/libpcap/)

# ---------------- Libraries --------------------
# Download submodules and apply patch to their source code
execute_process(
  COMMAND bash -c "./scripts/apply_patches.sh ./libs"
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

# Import wdissector library
set(WDISSECTOR_PATH
  ${PROJECT_SOURCE_DIR}/wdissector)
set(WDISSECTOR_INCLUDES
  ${GLIB_INCLUDE_DIRS}
  ${WDISSECTOR_PATH}/src/
  ${WDISSECTOR_PATH}/libs/wireshark
  ${WDISSECTOR_PATH}/libs/wireshark/include)
  message("WDISSECTOR_PATH=${WDISSECTOR_PATH}")

# Ensure correct symlink to wdissector bin folder
if(NOT IS_SYMLINK ${PROJECT_SOURCE_DIR}/bin)
  message(INFO "Removing invalid bin folder")
  exec_program("rm -rdf ${PROJECT_SOURCE_DIR}/bin")
endif()
exec_program("ln -sfT ${WDISSECTOR_PATH}/bin  ${PROJECT_SOURCE_DIR}/bin")
exec_program("cp ${WDISSECTOR_PATH}/configs/global_config.json ${PROJECT_SOURCE_DIR}/configs/global_config.json")

add_library(wdissector SHARED IMPORTED)
set_property(
  TARGET wdissector PROPERTY IMPORTED_LOCATION
  "${PROJECT_SOURCE_DIR}/bin/libwdissector.so")
target_include_directories(wdissector INTERFACE ${WDISSECTOR_INCLUDES})

# libboost
set(LIBBOOST_DOWNLOAD_DIR ${PROJECT_SOURCE_DIR}/libs/libboost/)
set(LIBBOOST_DOWNLOAD_URL https://www.mirrorservice.org/sites/tinycorelinux.net/13.x/x86_64/tcz/src/boost/boost_1_78_0.tar.gz)
string(REGEX MATCH "boost_[^.]*" LIBBOOST_VERSION "${LIBBOOST_DOWNLOAD_URL}")
set(BOOST_ROOT ${LIBBOOST_DOWNLOAD_DIR}/${LIBBOOST_VERSION}/)
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_NO_WARN_NEW_VERSIONS 1)

if(NOT EXISTS ${LIBBOOST_DOWNLOAD_DIR}/boost)
  message(STATUS "Downloading libboost")
  file(
    DOWNLOAD
    ${LIBBOOST_DOWNLOAD_URL}
    ${PROJECT_SOURCE_DIR}/libs/libboost/boost.tar.gz
    SHOW_PROGRESS)

  # 1) Extract libboost
  execute_process(
    COMMAND bash -c "tar -xf boost.tar.gz && ln -sfn ${LIBBOOST_VERSION}/boost boost && sync && rm boost.tar.gz"
    WORKING_DIRECTORY ${LIBBOOST_DOWNLOAD_DIR})

  # 2) Compile libboost required modules
  execute_process(
    COMMAND bash -c "sync && ./bootstrap.sh && sync && ./b2 --with-serialization --with-iostreams --with-context --with-filesystem --with-program_options --with-regex --with-system --with-thread"
    WORKING_DIRECTORY ${LIBBOOST_DOWNLOAD_DIR}/${LIBBOOST_VERSION}/)
endif()

if(NOT EXISTS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libboost_serialization.so)
  # 3) Copy boost binaries to bin folder
  execute_process(
    COMMAND bash -c "mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} && sync && find ./stage/lib -name '*.so*' -exec cp -prv '{}' '${CMAKE_RUNTIME_OUTPUT_DIRECTORY}' ';'"
    WORKING_DIRECTORY ${LIBBOOST_DOWNLOAD_DIR}/${LIBBOOST_VERSION}/)
endif()

find_package(Boost 1.51.0 MODULE
  COMPONENTS
  context
  filesystem
  program_options
  regex
  system
  thread
  serialization
  iostreams
  REQUIRED
)

# libPCAP
add_subdirectory(${PROJECT_SOURCE_DIR}/libs/libpcap)
set(HAVE_LIBPCAP 1)
set(ENABLE_PCAP ON)
set(CAN_SET_CAPTURE_BUFFER_SIZE 1)
set(PCAP_FOUND ON)

# Cross-platform serial library
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(${PROJECT_SOURCE_DIR}/libs/serialport)
set(BUILD_SHARED_LIBS ON)
target_include_directories(serial INTERFACE ${PROJECT_SOURCE_DIR}/libs/serialport/include)

# react-cpp (event loop library)
add_subdirectory(${PROJECT_SOURCE_DIR}/libs/react-cpp/)

# Pcap PlusPlus
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(${PROJECT_SOURCE_DIR}/libs/PcapPlusPlus/)
set(BUILD_SHARED_LIBS ON)
set(PcapPlusPlus CommonPP PacketPP PcapPP)
include_directories(
  libs/PcapPlusPlus/Pcap++/header/
  libs/PcapPlusPlus/Packet++/header/
  libs/PcapPlusPlus/Common++/header/)

# Import libfmt (static build)
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(libs/fmt)
set(BUILD_SHARED_LIBS ON)

# Import double-conversion (folly dependency)
set(DOUBLE_CONVERSION_LIBRARY double-conversion)
set(DOUBLE_CONVERSION_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/libs/double-conversion/double-conversion/)
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(libs/double-conversion)
set(BUILD_SHARED_LIBS ON)

set(BUILD_SHARED_LIBS OFF)
add_subdirectory(libs/folly)
target_include_directories(folly PUBLIC libs/folly/folly)
set(BUILD_SHARED_LIBS ON)

add_library(nanolog STATIC libs/NanoLog.cpp)
target_include_directories(nanolog PRIVATE ${PROJECT_SOURCE_DIR}/)

# Import Argparse library
FetchContent_Declare(
  argparse
  GIT_REPOSITORY https://github.com/p-ranav/argparse.git
)
FetchContent_MakeAvailable(argparse)

# ---------------- Targets --------------------

# Common Fuzzer libs
set(COMMON_LIBS
  ${CMAKE_THREAD_LIBS_INIT}
  argparse
  fmt
  folly
  nanolog
  ${PcapPlusPlus}
  serial
  reactcpp
  wdissector)

# ------- Fuzzers -------

# LTEFuzzer executable
set(VAKTBLE_SRC src/vaktble.cpp libs/profiling.c)
add_executable(vaktble ${VAKTBLE_SRC})
target_link_libraries(vaktble PRIVATE ${COMMON_LIBS})
target_compile_options(vaktble PRIVATE -w -O0 -g3 -fno-eliminate-unused-debug-symbols)
target_precompile_headers(vaktble PRIVATE src/vaktble.hpp)
