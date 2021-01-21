cmake_minimum_required(VERSION 3.5)

project(sframe
  VERSION 0.1
  LANGUAGES CXX
)

option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(ADDRESS_SANITIZER "Enable address sanitizer" OFF)

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)
endif()

if (ADDRESS_SANITIZER)
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -fsanitize=address")
  set (CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS} -fsanitize=address")
  set (CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    -fsanitize=address")
  set (CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
  set (CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")
endif()

if(CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY  ${CLANG_TIDY_EXE})
  else()
    message(WARNING "clang-tidy requested, but not found")
  endif()
endif()

###
### Dependencies
###

# External libraries
find_package(OpenSSL 1.1 REQUIRED)

# gsl-lite fetched from GitHub
include( ExternalProject )
find_package( Git REQUIRED )
set( GSL_LITE_URL https://github.com/gsl-lite/gsl-lite.git )
set_directory_properties( PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/third_party )

ExternalProject_Add(
    gsl-extern
    GIT_REPOSITORY ${GSL_LITE_URL}
    TIMEOUT 10
    UPDATE_COMMAND ${GIT_EXECUTABLE} pull
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
   )

ExternalProject_Get_Property( gsl-extern SOURCE_DIR )
set( GSL_LITE_INCLUDE_DIR ${SOURCE_DIR}/include CACHE INTERNAL "Include folder for gsl-lite" )

add_library( gsl INTERFACE )
add_dependencies(gsl gsl-extern)
target_include_directories( gsl INTERFACE ${GSL_LITE_INCLUDE_DIR} )

###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${LIB_NAME} gsl)
target_link_libraries(${LIB_NAME} PRIVATE gsl OpenSSL::Crypto)
target_include_directories(${LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

###
### Tests
###

add_subdirectory(test)

