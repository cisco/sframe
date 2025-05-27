set(PACKAGE_NAME "STM32Cryptographic")
set(LIBRARY_NAME "STM32Cryptographic")

# Locate the include directory
find_path(
    STM32Cryptographic_INCLUDE_DIR
    "cmox_crypto.h"
    PATHS
        ${STM32Cryptographic_ROOT_DIR}
        /usr/local/include
        /usr/include
    PATH_SUFFIXES include
)

if(NOT STM32Cryptographic_INCLUDE_DIR)
    message(WARNING "Could not find include dir for ${PACKAGE_NAME}")
else()
    message(STATUS "Found include dir: ${STM32Cryptographic_INCLUDE_DIR}")
endif()

function(find_stm32_crypto_library LIBRARY_NAME)
    find_library(
        ${LIBRARY_NAME}
        NAMES ${LIBRARY_NAME}
        PATHS
            ${STM32Cryptographic_ROOT_DIR}
            /usr/local/lib
            /usr/lib
        PATH_SUFFIXES lib
        NO_DEFAULT_PATH
    )

    if(NOT ${LIBRARY_NAME})
        message(WARNING "Could not find library: ${LIBRARY_NAME}")
    else()
        message(STATUS "Found library: ${LIBRARY_NAME} at ${${LIBRARY_NAME}}")
    endif()

    set(STM32Cryptographic_LIBRARY "${STM32Cryptographic_LIBRARY} ${STM32_CRYPTO_LIBRARY}" PARENT_SCOPE)
endfunction()

# Locate the libraries
find_stm32_crypto_library(STM32Cryptographic_CM0_CM0PLUS)
find_stm32_crypto_library(STM32Cryptographic_CM3)
find_stm32_crypto_library(STM32Cryptographic_CM33)
find_stm32_crypto_library(STM32Cryptographic_CM4)
find_stm32_crypto_library(STM32Cryptographic_CM7)

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
