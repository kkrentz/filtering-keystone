cmake_minimum_required(VERSION 3.10)
project(keystone_sdk C CXX ASM)
include(macros.cmake)

#-------------------------------------------------------------------------------
# BASIC SETUP
#-------------------------------------------------------------------------------

set(prog_name    keystone-sdk)
set(src_dir      ${CMAKE_CURRENT_LIST_DIR})
set(scripts_dir  ${src_dir}/scripts)

if (DEFINED KEYSTONE_SDK_DIR)
  if (NOT IS_ABSOLUTE ${KEYSTONE_SDK_DIR})
    message(FATAL_ERROR "KEYSTONE_SDK_DIR needs to be absolute path")
  endif()
  get_filename_component(KEYSTONE_SDK_DIR ${KEYSTONE_SDK_DIR} ABSOLUTE)
  set(out_dir    ${KEYSTONE_SDK_DIR})
else()
  message(FATAL_ERROR " * Set KEYSTONE_SDK_DIR to the path you want to install the SDK.\n"
    " * Try `export KEYSTONE_SDK_DIR=<path/to/SDK>`")
  set(out_dir    ${CMAKE_BINARY_DIR})
endif()

if (${out_dir} STREQUAL ${CMAKE_SOURCE_DIR})
  message(FATAL_ERROR "OUTPUT_DIR must be different from the source path")
endif()

message(" *** Install path: ${out_dir}")

#-------------------------------------------------------------------------------
# Program and flags
#-------------------------------------------------------------------------------

if (KEYSTONE_ATTESTATION STREQUAL "sigma")
    string(APPEND CMAKE_C_FLAGS "-DWITH_FHMQVC=0 -DWITH_FHMQV=0 -DWITH_TINY_DICE=0")
    string(APPEND CMAKE_CXX_FLAGS "-DWITH_FHMQVC=0 -DWITH_FHMQV=0 -DWITH_TINY_DICE=0")
elseif (KEYSTONE_ATTESTATION STREQUAL "trap")
    string(APPEND CMAKE_C_FLAGS "-DWITH_FHMQVC=1 -DWITH_FHMQV=1 -DWITH_TINY_DICE=0")
    string(APPEND CMAKE_CXX_FLAGS "-DWITH_FHMQVC=1 -DWITH_FHMQV=1 -DWITH_TINY_DICE=0")
elseif (KEYSTONE_ATTESTATION STREQUAL "irap")
    string(APPEND CMAKE_C_FLAGS "-DWITH_FHMQVC=0 -DWITH_FHMQV=1 -DWITH_TINY_DICE=1")
    string(APPEND CMAKE_CXX_FLAGS "-DWITH_FHMQVC=0 -DWITH_FHMQV=1 -DWITH_TINY_DICE=1")
else()
    message(FATAL_ERROR "KEYSTONE_ATTESTATION must either be sigma, trap, or irap instead of ${KEYSTONE_ATTESTATION}")
endif()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE    "Debug")
else()
    if ((NOT CMAKE_BUILD_TYPE STREQUAL "Debug") AND (NOT CMAKE_BUILD_TYPE STREQUAL "Release"))
    message(FATAL_ERROR "CMAKE_BUILD_TYPE must either be Debug or Release instead of ${CMAKE_BUILD_TYPE}")
    endif()
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -g)
endif()

use_riscv_toolchain(${KEYSTONE_BITS})
################################################################################
# BUILD PROJECTS
################################################################################
include_directories(
  include
  $ENV{KEYSTONE_SM}/src
  $ENV{KEYSTONE_SM}/src/libcoap/ext/micro-ecc
)
add_subdirectory(src)
install(FILES macros.cmake DESTINATION ${out_dir}/cmake/)

################################################################################
# Auto Formatting
################################################################################
file(GLOB_RECURSE
  CHECK_CXX_SOURCE_FILES
  src/*.cpp include/*.hpp
  example/*.cpp tests/*.cpp
  example/*.hpp tests/*.hpp
)

# remove external cpp sources from cpplint checking
list(FILTER CHECK_CXX_SOURCE_FILES EXCLUDE REGEX ".*/json11.cpp$")
list(FILTER CHECK_CXX_SOURCE_FILES EXCLUDE REGEX ".*/json11.h$")

file(GLOB_RECURSE
  CHECK_C_SOURCE_FILES
  src/*.c include/*.h
  example/*.c tests/*.c
  example/*.h tests/*.h
)

find_program(CLANG_FORMAT "clang-format")
find_program(CPPLINT "cpplint")

if(CLANG_FORMAT AND CPPLINT)
  add_custom_target(
    format
    COMMAND
      ${CLANG_FORMAT}
      -i
      -style=file
      ${CHECK_CXX_SOURCE_FILES} ${CHECK_C_SOURCE_FILES}
    COMMAND
      ${CPPLINT}
      ${CHECK_CXX_SOURCE_FILES}
    COMMENT "Auto-formatting"
  )
endif()

################################################################################
# Uninstall
################################################################################
add_custom_target("uninstall"
  COMMAND
  rm -rf ${out_dir}/lib
  rm -rf ${out_dir}/include
  rm -rf ${out_dir}/cmake)

add_subdirectory(tests EXCLUDE_FROM_ALL)
add_subdirectory(.post-install)
