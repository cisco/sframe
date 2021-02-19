# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
BUILD_CONFIG=Release
CLANG_FORMAT=clang-format -i

TEST_VECTOR_DIR=./build/test
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all tidy test clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target sframe --config ${BUILD_CONFIG}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug .

tidy:
	cmake -B${BUILD_DIR} -DCLANG_TIDY=ON -DCMAKE_BUILD_TYPE=Debug .

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target sframe_test --config ${BUILD_CONFIG}
	cd ${TEST_VECTOR_DIR} && ctest

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find include -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}

