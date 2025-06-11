cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(BinSight C)

# Set default build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose build type" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Enable debug symbols explicitly
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -g3")

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMAGIC REQUIRED libmagic)
pkg_check_modules(NCURSES REQUIRED ncurses)

file(GLOB_RECURSE SOURCES "src/*.c")

add_executable(binsight ${SOURCES})

target_include_directories(binsight PRIVATE src include ${LIBMAGIC_INCLUDE_DIRS} ${NCURSES_INCLUDE_DIRS})
target_compile_options(binsight PRIVATE ${LIBMAGIC_CFLAGS} ${NCURSES_CFLAGS})
target_link_libraries(binsight PRIVATE ${LIBMAGIC_LIBRARIES} ${NCURSES_LIBRARIES})
