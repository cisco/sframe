cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(SFrameTests
  LANGUAGES CXX
)

# Dependencies

find_package(doctest REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)

# Test Binary

file(GLOB sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(SFrameTests ${sources})
target_link_libraries(SFrameTests doctest::doctest SFrame OpenSSL::Crypto)

set_target_properties(SFrameTests PROPERTIES CXX_STANDARD 17)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(SFrame PUBLIC -Wall -pedantic -Wextra -Werror)
elseif(MSVC)
  target_compile_options(SFrame PUBLIC /W4 /WX)
endif()

# TODO Enable CTest
# doctest_discover_tests(SFrameTests)
