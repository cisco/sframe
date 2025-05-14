set(PACKAGE_NAME "STM32Cryptographic")
set(LIBRARY_NAME "STM32Cryptographic")

# Locate the include directory
find_path(
    STM32Cryptographic_INCLUDE_DIR
    PATHS
        ${STM32Cryptographic_ROOT_DIR}
        /usr/local/include
        /usr/include
    PATH_SUFFIXES include
)

# Locate the library
find_library(
    STM32Cryptographic_LIBRARY
    PATHS
        ${STM32Cryptographic_ROOT_DIR}
        /usr/local/lib
        /usr/lib
    PATH_SUFFIXES lib
)

# Set the STM32Cryptographic_FOUND variable
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(${PACKAGE_NAME}
    REQUIRED_VARS
        STM32Cryptographic_INCLUDE_DIR
        STM32Cryptographic_LIBRARY
)

# Set output variables
if(${PACKAGE_NAME}_FOUND)
    set(STM32Cryptographic_INCLUDE_DIRS ${STM32Cryptographic_INCLUDE_DIR})
    set(STM32Cryptographic_LIBRARIES ${STM32Cryptographic_LIBRARY})
else()
    set(STM32Cryptographic_INCLUDE_DIRS "")
    set(STM32Cryptographic_LIBRARIES "")
endif()

# Set compile definitions (if any)
# list(APPEND STM32Cryptographic_DEFINITIONS "-DSTM32Cryptographic_ENABLE_FEATURE")

mark_as_advanced(
    STM32Cryptographic_INCLUDE_DIR
    STM32Cryptographic_LIBRARY
)
