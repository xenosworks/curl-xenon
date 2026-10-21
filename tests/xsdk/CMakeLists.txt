#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
# Checks curl on the Xbox 360 through xsdk (docs/README-xsdk.md), with
# mbedtls-xenon checked out beside this repository. Build xsdk first, then:
#   cmake -S tests/xsdk -B build-xsdk-check -GNinja \
#       -DCMAKE_TOOLCHAIN_FILE=<xsdk>/cmake/xsdk.cmake -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-xsdk-check
cmake_minimum_required(VERSION 3.18)
project(curl_xsdk_checks C)

set(MBEDTLS_XENON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbedtls-xenon"
  CACHE PATH "mbedtls-xenon's checkout")
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory("${MBEDTLS_XENON_DIR}" mbedtls)

# curl takes mbedtls-xenon's own targets, which carry the configuration Mbed
# TLS is built with.
set(MBEDTLS_INCLUDE_DIR "${MBEDTLS_XENON_DIR}/include" CACHE PATH "")
set(MBEDTLS_LIBRARY mbedtls CACHE STRING "")
set(MBEDX509_LIBRARY mbedx509 CACHE STRING "")
set(MBEDCRYPTO_LIBRARY mbedcrypto CACHE STRING "")
set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory(../.. curl)

# cJSON 1.7.19's two files, as upstream ships them.
add_executable(curl_check curl_check.c cjson/cJSON.c)
target_include_directories(curl_check PRIVATE cjson)
target_link_libraries(curl_check PRIVATE CURL::libcurl mbedtls)
target_compile_options(curl_check PRIVATE -Wall -Wextra -Werror)
xsdk_add_xex(curl_check TITLE_ID 0x58534355 NAME "curl_check")

# Beside the title: Mozilla's roots, as mbedtls-xenon's checks have them, and
# Mbed TLS's test CA, which net_http.py's certificate for localhost is under.
configure_file("${MBEDTLS_XENON_DIR}/programs/xsdk/cacert.pem" cacert.pem
  COPYONLY)
configure_file("${MBEDTLS_XENON_DIR}/framework/data_files/test-ca2.crt"
  test-ca2.crt COPYONLY)
