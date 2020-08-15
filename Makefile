# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# choose: Ninja, Unix Makefiles, Xcode, or leave blank for default
GENERATOR=-G Ninja
BUILD_DIR=build
CLANG_FORMAT=clang-format

.PHONY: all test clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target SFrame

test: all
	cmake --build ${BUILD_DIR} --target SFrameTests
	cd ${BUILD_DIR} && ctest

${BUILD_DIR}: CMakeLists.txt
	cmake ${GENERATOR} -B${BUILD_DIR} .

clean:
	cd ${BUILD_DIR} && ninja clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	${CLANG_FORMAT} -i src/*
	${CLANG_FORMAT} -i include/sframe/*
	${CLANG_FORMAT} -i test/*
