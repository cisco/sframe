set(TEST_APP_NAME "${LIB_NAME}_test")

# Dependencies
find_package(doctest REQUIRED)

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

message("INCLUDE:: ${CMAKE_PROJECT_SOURCE_DIR}/src")
add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
target_include_directories(${TEST_APP_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(${TEST_APP_NAME} ${LIB_NAME} doctest::doctest OpenSSL::Crypto)

# Enable CTest
include(doctest)
doctest_discover_tests(${TEST_APP_NAME}
                       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
