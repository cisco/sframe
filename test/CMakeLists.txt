cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(SFrameTests
  LANGUAGES CXX
)

# Dependencies
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
find_package(SFrame REQUIRED)
find_package(doctest REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)

# Test Binary
file(GLOB sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(SFrameTests ${sources})
target_link_libraries(SFrameTests doctest::doctest SFrame::SFrame OpenSSL::Crypto)

set_property(TARGET SFrameTests PROPERTY CXX_STANDARD 17)
set_property(TARGET SFrameTests PROPERTY CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(SFrameTests PUBLIC -Wall -pedantic -Wextra -Werror)
elseif(MSVC)
  target_compile_options(SFrameTests PUBLIC /W4 /WX)
endif()

# Enable CTest
include(doctest)
enable_testing()
doctest_discover_tests(SFrameTests)
