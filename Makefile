# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
CLANG_FORMAT=clang-format -i

TEST_VECTOR_DIR=./build/test
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all tidy test clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target sframe

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR} .

dev: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug -DCLANG_TIDY=ON -DTESTING=ON -DSANITIZERS=ON .

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target sframe_test
	cd ${TEST_VECTOR_DIR} && ctest

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find include -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}

