# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# choose: Ninja, Unix Makefiles, Xcode, or leave blank for default
GENERATOR=-G Ninja
LIB_DIR=../build
BUILD_DIR=build
CLANG_FORMAT=clang-format

.PHONY: all tidy test clean cclean

all: ${BUILD_DIR} ${LIB_DIR}
	cmake --build ${BUILD_DIR}

test: all
	cd ${BUILD_DIR} && ctest

tidy:
	cmake ${GENERATOR} -B${BUILD_DIR} ${CMAKE_FLAGS} -DCLANG_TIDY=ON .

${BUILD_DIR}: CMakeLists.txt
	cmake ${GENERATOR} -B${BUILD_DIR} ${CMAKE_FLAGS} .

clean:
	cd ${BUILD_DIR} && ninja clean

cclean:
	rm -rf ${BUILD_DIR}
