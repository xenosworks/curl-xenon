<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Xbox 360 (xsdk)

libcurl for the Xbox 360 through [xsdk](https://github.com/xenosworks/xsdk), a homebrew SDK that builds titles for
the console's retail kernel, with TLS from [mbedtls-xenon](https://github.com/xenosworks/mbedtls-xenon). This is an
altered version of curl 8.23.0; the changes are on the `xenon` branch.

## Building

Build xsdk first (`make` in its checkout builds `libxsdk.a`), then Mbed TLS, installed where curl finds its CMake
package:

```bash
cmake -S <mbedtls-xenon> -B build-mbedtls -GNinja -DCMAKE_TOOLCHAIN_FILE=<xsdk>/cmake/xsdk.cmake \
    -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DCMAKE_INSTALL_PREFIX=<prefix>
cmake --build build-mbedtls && cmake --install build-mbedtls
cmake -S. -Bbuild-xsdk -GNinja -DCMAKE_TOOLCHAIN_FILE=<xsdk>/cmake/xsdk.cmake -DCMAKE_BUILD_TYPE=Release \
    -DMbedTLS_DIR=<prefix>/lib/cmake/MbedTLS
cmake --build build-xsdk
```

That builds `lib/libcurl.a`, static, without the curl tool. A title can instead add mbedtls-xenon and curl to its own
CMake build, as `tests/xsdk/CMakeLists.txt` does, and link `CURL::libcurl`; it turns its ELF into a `.xex` with
xsdk's `xsdk_add_xex()`.

## Notes

-   HTTP and HTTPS only. `CMake/xsdk.cmake`, which `CMakeLists.txt` takes in when xsdk's toolchain file sets `XSDK`,
    turns every other protocol off, and proxies, cookies, netrc, Alt-Svc, HSTS, IPv6, zlib, brotli, zstd, nghttp2,
    libpsl, libssh2 and libidn2 with them. Each is a cache default, so `-D` on the command line still wins.
-   TLS 1.2 through mbedtls-xenon. curl has to be compiled with the configuration Mbed TLS was built with, which
    mbedtls-xenon's CMake package and targets carry (`MBEDTLS_USER_CONFIG_FILE`), so find it through those and not
    through its headers and libraries alone.
-   No built-in CA bundle: a title gives `CURLOPT_CAINFO`, such as a `cacert.pem` beside its `.xex`. Certificates are
    checked against the console's clock, which has to be right.
-   Names resolve on curl's threaded resolver over xsdk's pthreads, so `CURLOPT_CONNECTTIMEOUT` covers a lookup, which
    xsdk's `getaddrinfo` can hold for 30 s.
-   No socket pair (`CURL_DISABLE_SOCKETPAIR`): curl's binds 127.0.0.1, which XAM refuses. So `curl_multi_wakeup` isn't
    there, and `curl_multi_poll` waits until a socket is ready or its timeout ends.
-   Build with an xsdk toolchain that keeps LR to 32-bit values, as mbedtls-xenon's notes say.

## The check title

`tests/xsdk` builds `curl_check.xex`, which walks a homebrew store's path against xsdk's `tools/net_http.py` on the PC:

```bash
cmake -S tests/xsdk -B build-xsdk-check -GNinja -DCMAKE_TOOLCHAIN_FILE=<xsdk>/cmake/xsdk.cmake \
    -DCMAKE_BUILD_TYPE=Release [-DMBEDTLS_XENON_DIR=<mbedtls-xenon>]
cmake --build build-xsdk-check
```

mbedtls-xenon is taken from beside this repository unless `MBEDTLS_XENON_DIR` names it. Beside `curl_check.xex` go:

-   `cacert.pem` and `test-ca2.crt`, which the build puts beside it: Mozilla's roots as mbedtls-xenon's checks have
    them, and Mbed TLS's test CA, which `net_http.py`'s certificate for `localhost` is under;
-   `net_http.txt`, the PC's address and `net_http.py`'s HTTP port, as `192.168.0.125 7380`; HTTPS is on the next port;
-   to break one check on purpose, `curl_check_break.txt` naming it: `pc_trusts_cacert`, `verifyhost_off`,
    `follow_off`, `no_timeout`, `refused_answers` or `unknown_answers`. `net_http.py --break` gives the others.

It logs `PASS` or `FAIL` for each check, then the download rates, then `tests: <passed> passed, <failed> failed`. It
first downloads xsdk's `launch_target.xex` beside itself and launches it, and that launches `curl_check` back, whose
log, written anew, has every check.

It reads its catalogue with cJSON 1.7.19 (MIT), whose two files are in `tests/xsdk/cjson` as upstream ships them
(https://github.com/DaveGamble/cJSON/releases/tag/v1.7.19); a title adds them to its sources.
