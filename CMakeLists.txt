
cmake_minimum_required(VERSION 3.1 )

project(SFrame 
  VERSION 0.1
  LANGUAGES CXX
)

find_package(OpenSSL 1.1 REQUIRED)



FILE(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
FILE(GLOB_RECURSE sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp") 


add_library(SFrame ${headers} ${sources})

set_target_properties(SFrame PROPERTIES CXX_STANDARD 17)

target_link_libraries(SFrame PRIVATE OpenSSL::Crypto)

target_include_directories(SFrame
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)


#add_executable ( sframe test/sframe.cpp )
# enable_testing()
#add_test( NAME sframe COMMAND sframe )


