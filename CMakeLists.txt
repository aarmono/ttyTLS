cmake_minimum_required(VERSION 3.5)
project(ttyTLS)

if (CONFIG_BIG_ENDIAN)
    set(CMAKE_C_BYTE_ORDER    BIG_ENDIAN)
    set(CMAKE_CXX_BYTE_OREDER BIG_ENDIAN)
else ()
    set(CMAKE_C_BYTE_ORDER    LITTLE_ENDIAN)
    set(CMAKE_CXX_BYTE_OREDER LITTLE_ENDIAN)
endif()


find_path(
  WOLFSSL_INCLUDE_DIR
  NAMES "wolfssl/ssl.h"
  REQUIRED)

find_library(
  WOLFSSL_LIB
  "wolfssl"
  REQUIRED)

message(STATUS "WOLFSSL_INCLUDE_DIR => ${WOLFSSL_INCLUDE_DIR}")
message(STATUS "WOLFSSL_LIB => ${WOLFSSL_LIB}")

add_executable(ttyTLS ttyTLS.c)
target_compile_definitions(ttyTLS PUBLIC -D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED -D_DEFAULT_SOURCE)
target_link_libraries(ttyTLS ${CMAKE_REQUIRED_LIBRARIES} ${WOLFSSL_LIB} m)