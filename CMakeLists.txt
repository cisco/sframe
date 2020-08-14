cmake_minimum_required(VERSION 3.12)

project(SFrame 
  VERSION 0.1
  LANGUAGES CXX
)

# Dependencies 
find_package(OpenSSL 1.1 REQUIRED)

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

# Test

add_subdirectory(test)
