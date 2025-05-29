set(PACKAGE_NAME "STM32Cryptographic")
set(LIBRARY_NAME "STM32Cryptographic")

list(LENGTH ${PACKAGE_NAME}_FIND_COMPONENTS components_length)
if (components_length EQUAL 0)
    message(FATAL_ERROR "STM32 Crypto requires specific component(s) be requested (CM0_CM0PLUS, CM3, CM33, CM4, CM7)")
endif()

list(FIND ${PACKAGE_NAME}_FIND_COMPONENTS "CM0_CM0PLUS" cm0_cm0plus_requested)
list(FIND ${PACKAGE_NAME}_FIND_COMPONENTS "CM3" cm3_requested)
list(FIND ${PACKAGE_NAME}_FIND_COMPONENTS "CM33" cm33_requested)
list(FIND ${PACKAGE_NAME}_FIND_COMPONENTS "CM4" cm4_requested)
list(FIND ${PACKAGE_NAME}_FIND_COMPONENTS "CM7" cm7_requested)

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

    set(STM32Cryptographic_LIBRARY "${STM32Cryptographic_LIBRARY};${${LIBRARY_NAME}}" PARENT_SCOPE)
endfunction()

# Locate the libraries
if (cm0_cm0plus_requested GREATER -1)
    message(STATUS "Requested crypto library for CM0_CM0PLUS cortex, searching...")
    find_stm32_crypto_library(STM32Cryptographic_CM0_CM0PLUS)
endif()
if (cm3_requested GREATER -1)
    message(STATUS "Requested crypto library for CM3 cortex, searching...")
    find_stm32_crypto_library(STM32Cryptographic_CM3)
endif()
if (cm33_requested GREATER -1)
    message(STATUS "Requested crypto library for CM33 cortex, searching...")
    find_stm32_crypto_library(STM32Cryptographic_CM33)
endif()
if (cm4_requested GREATER -1)
    message(STATUS "Requested crypto library for CM4 cortex, searching...")
    find_stm32_crypto_library(STM32Cryptographic_CM4)
endif()
if (cm7_requested GREATER -1)
    message(STATUS "Requested crypto library for CM7 cortex, searching...")
    find_stm32_crypto_library(STM32Cryptographic_CM7)
endif()

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
