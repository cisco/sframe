cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(SFrameTests
  LANGUAGES CXX
)

# Dependencies
find_package(doctest REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)

# SFrame
set(SFRAME_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/../include)
set(SFRAME_BINARY_DIR ${PROJECT_SOURCE_DIR}/../build)

# Test Binary

file(GLOB sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(SFrameTests ${sources})
target_include_directories(SFrameTests PRIVATE ${SFRAME_INCLUDE_DIR})
target_link_directories(SFrameTests PRIVATE ${SFRAME_BINARY_DIR})
target_link_libraries(SFrameTests doctest::doctest SFrame OpenSSL::Crypto)

set_target_properties(SFrameTests PROPERTIES CXX_STANDARD 17)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(SFrameTests PUBLIC -Wall -pedantic -Wextra -Werror)
elseif(MSVC)
  target_compile_options(SFrameTests PUBLIC /W4 /WX)
endif()

# Enable CTest
include(doctest)
enable_testing()
doctest_discover_tests(SFrameTests)
