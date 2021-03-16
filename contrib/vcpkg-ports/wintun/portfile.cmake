set(VCPKG_POLICY_DLLS_WITHOUT_LIBS enabled)
if (VCPKG_TARGET_ARCHITECTURE STREQUAL "x86")
    set(WINTUN_ARCH "x86")
elseif (VCPKG_TARGET_ARCHITECTURE STREQUAL "x64")
    set(WINTUN_ARCH "amd64")
elseif (VCPKG_TARGET_ARCHITECTURE STREQUAL "arm64")
    set(WINTUN_ARCH "arm64")
else()
    message(FATAL_ERROR "Unsupported architecture: ${VCPKG_TARGET_ARCHITECTURE}")
endif()

vcpkg_download_distfile(ARCHIVE
    URLS https://www.wintun.net/builds/wintun-0.14.1.zip
    FILENAME wintun-0.14.1.zip
    SHA512 1b2e393b5ea76236c5204d713955b80aa0f90049152b2a02fe6a4e499bfaf3ee6a8019f8413130c49b0ae29cf6091afec0437a04caa08420d1530466b0a48ff0
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    REF ${7ZIP_VERSION}
)

file(COPY ${SOURCE_PATH}/include/wintun.h DESTINATION ${CURRENT_PACKAGES_DIR}/include/)
file(COPY
    ${SOURCE_PATH}/bin/${WINTUN_ARCH}/wintun.dll
    DESTINATION ${CURRENT_PACKAGES_DIR}/bin/)
file(COPY
    ${SOURCE_PATH}/bin/${WINTUN_ARCH}/wintun.dll
    DESTINATION ${CURRENT_PACKAGES_DIR}/debug/bin/)

file(INSTALL
    ${SOURCE_PATH}/LICENSE.txt
    DESTINATION ${CURRENT_PACKAGES_DIR}/share/wintun RENAME copyright)
