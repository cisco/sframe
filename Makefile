# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# choose: Ninja, Unix Makefiles, Xcode, or leave blank for default
GENERATOR=-G Ninja
BUILD_DIR=build

.PHONY: all lint test gen gen_debug example clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR}

${BUILD_DIR}: CMakeLists.txt
	cmake -H. ${GENERATOR} -B${BUILD_DIR}

clean:
	cd ${BUILD_DIR} && ninja clean

cclean:
	rm -rf ${BUILD_DIR}
