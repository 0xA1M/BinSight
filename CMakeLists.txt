cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(BinSight C CXX)
enable_testing()

# Enforce out-of-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds are not allowed. Please use: cmake -S . -B build")
endif()

# Set standards
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)

# Default build type = Debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# --- Build type flags ---
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  set(CMAKE_C_FLAGS_DEBUG "-g3")
  set(CMAKE_CXX_FLAGS_DEBUG "-g3")
  set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -s")
endif()

# Warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMAGIC REQUIRED libmagic)
pkg_check_modules(NCURSES REQUIRED ncurses)

# Core library sources
file(GLOB_RECURSE SOURCES "src/*.c")
list(FILTER SOURCES EXCLUDE REGEX "src/main.c")

# Core library
add_library(binsight_core ${SOURCES})
target_include_directories(binsight_core
  PUBLIC
    ${CMAKE_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBMAGIC_INCLUDE_DIRS}
    ${NCURSES_INCLUDE_DIRS}
)
target_link_libraries(binsight_core
  PRIVATE
    ${LIBMAGIC_LIBRARIES}
    ${NCURSES_LIBRARIES}
)

# Main executable
add_executable(binsight src/main.c)
target_link_libraries(binsight PRIVATE binsight_core)

# Tests
add_subdirectory(tests)
