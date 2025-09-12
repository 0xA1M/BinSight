include(FetchContent)

# Fetch GoogleTest if not installed system-wide
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0  # latest stable release
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Gather all test sources
file(GLOB_RECURSE TEST_SOURCES "*.cpp")

# Single unified test executable
add_executable(binsight_tests ${TEST_SOURCES})
target_include_directories(binsight_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(binsight_tests PRIVATE
  binsight_core
  GTest::gtest_main
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(binsight_tests)
