#!/bin/bash

export FREEDIAMETER_PREFIX=/opt/vowifi/freediameter
cmake -B build \
    -DMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=${FREEDIAMETER_PREFIX} \
    -DENABLE_APP_RADGW=ON -DENABLE_RGWX=ON \
    -DCMAKE_INSTALL_RPATH=/opt/vowifi/freediameter/lib \
    -DCMAKE_BUILD_RPATH=/opt/vowifi/freediameter/lib \
    -DBUILD_APP_VOWIFI:BOOL=ON \
    -DBUILD_APP_RADGW:BOOL=ON \
    -DBUILD_RGWX_AUTH:BOOL=ON \
    -DBUILD_RGWX_ACCT:BOOL=ON \
    -DBUILD_RGWX_ECHODROP:BOOL=ON \
    -DBUILD_RGWX_VOWIFI:BOOL=ON \
    -DBUILD_DICT_NASREQ:BOOL=ON \
    -DBUILD_DICT_EAP:BOOL=ON \
    -DBUILD_DICT_JSON:BOOL=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,-E" \
    -DCMAKE_INCLUDE_PATH="/usr/include;/usr/include/x86_64-linux-gnu" \
    -DCMAKE_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu;/usr/lib" \
    -DIDNA_INCLUDE_DIR="/usr/include" \
    -DIDNA_LIBRARY="/usr/lib/x86_64-linux-gnu/libidn.so" \
    -DGNUTLS_INCLUDE_DIR="/usr/include" \
    -DGNUTLS_LIBRARY="/usr/lib/x86_64-linux-gnu/libgnutls.so" \
    -DGCRYPT_INCLUDE_DIR="/usr/include" \
    -DGCRYPT_LIBRARY="/usr/lib/x86_64-linux-gnu/libgcrypt.so" \
    -DSCTP_INCLUDE_DIR="/usr/include" \
    -DSCTP_LIBRARY="/usr/lib/x86_64-linux-gnu/libsctp.so"

cmake --build build -j
cmake --install build
