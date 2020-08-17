cmake_minimum_required(VERSION 3.12)

project(SFrame 
  VERSION 0.1
  LANGUAGES CXX
)

option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(BUILD_TESTS "Build tests as well as the library" OFF)

# Dependencies 
find_package(OpenSSL 1.1 REQUIRED)

# Linting
if(CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY 
      "${CLANG_TIDY_EXE}"
    )
  else()
    message(WARNING "clang-tidy requested, but not found")
  endif()
endif()

# Library 
file(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp") 

add_library(SFrame ${headers} ${sources})

set_target_properties(SFrame PROPERTIES CXX_STANDARD 17)

target_include_directories(SFrame
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

# Export package for local development access
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
export(TARGETS SFrame FILE SFrameConfig.cmake NAMESPACE SFrame::)
export(PACKAGE SFrame)
