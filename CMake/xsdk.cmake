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
# Defaults for the Xbox 360 through xsdk (docs/README-xsdk.md): a static
# libcurl for HTTP and HTTPS on Mbed TLS, without the curl tool. They are
# cache defaults, so a -D on the command line still wins.

set(_xsdk_doc "Default for xsdk (CMake/xsdk.cmake)")

foreach(_xsdk_option IN ITEMS
    BUILD_CURL_EXE BUILD_SHARED_LIBS BUILD_TESTING BUILD_EXAMPLES
    BUILD_LIBCURL_DOCS BUILD_MISC_DOCS ENABLE_CURL_MANUAL
    CURL_USE_OPENSSL ENABLE_IPV6 ENABLE_UNIX_SOCKETS
    USE_NGHTTP2 USE_LIBIDN2 CURL_USE_LIBPSL CURL_USE_LIBSSH2)
  set(${_xsdk_option} OFF CACHE BOOL "${_xsdk_doc}")
endforeach()
foreach(_xsdk_option IN ITEMS CURL_ZLIB CURL_BROTLI CURL_ZSTD)
  set(${_xsdk_option} OFF CACHE STRING "${_xsdk_doc}")
endforeach()
set(BUILD_STATIC_LIBS ON CACHE BOOL "${_xsdk_doc}")
set(CURL_USE_MBEDTLS ON CACHE BOOL "${_xsdk_doc}")
# Mbed TLS's CMake package carries the configuration mbedtls-xenon was built
# with (MBEDTLS_USER_CONFIG_FILE), and curl has to see the same one.
set(CURL_USE_CMAKECONFIG ON CACHE BOOL "${_xsdk_doc}")

# A title brings its own roots, as CURLOPT_CAINFO.
set(CURL_CA_BUNDLE "none" CACHE STRING "${_xsdk_doc}")
set(CURL_CA_PATH "none" CACHE STRING "${_xsdk_doc}")

# HTTP and HTTPS only. The socket pair binds 127.0.0.1, which XAM refuses
# (xsdk:docs/HARDWARE.md, "XAM's sockets and loader, milestone 56").
foreach(_xsdk_feature IN ITEMS
    DICT FILE FTP GOPHER IMAP IPFS LDAP LDAPS MQTT POP3 RTSP SMTP TELNET TFTP
    WEBSOCKETS PROXY COOKIES NETRC ALTSVC HSTS SOCKETPAIR)
  set(CURL_DISABLE_${_xsdk_feature} ON CACHE BOOL "${_xsdk_doc}")
endforeach()
