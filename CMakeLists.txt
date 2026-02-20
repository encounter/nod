cmake_minimum_required(VERSION 3.23)
project(nod C)

include(FetchContent)

option(NOD_COMPRESS_BZIP2 "Enable BZIP2 support" ON)
option(NOD_COMPRESS_LZMA "Enable LZMA/LZMA2 support" ON)
option(NOD_COMPRESS_ZLIB "Enable zlib/deflate support" ON)
option(NOD_COMPRESS_ZSTD "Enable Zstandard support" ON)
option(NOD_THREADING "Enable threaded processing support" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(NodCompressionDeps)

# Fetch Corrosion, allowing us to import the nod-ffi crate as a CMake target.
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

set(NOD_FEATURES)
if (NOD_COMPRESS_BZIP2)
    list(APPEND NOD_FEATURES compress-bzip2)
endif()
if (NOD_COMPRESS_LZMA)
    list(APPEND NOD_FEATURES compress-lzma)
endif()
if (NOD_COMPRESS_ZLIB)
    list(APPEND NOD_FEATURES compress-zlib)
endif()
if (NOD_COMPRESS_ZSTD)
    list(APPEND NOD_FEATURES compress-zstd)
endif()
if (NOD_THREADING)
    list(APPEND NOD_FEATURES threading)
endif()

set(NOD_IMPORT_ARGS NO_DEFAULT_FEATURES)
if (NOD_FEATURES)
    list(APPEND NOD_IMPORT_ARGS FEATURES ${NOD_FEATURES})
endif()
# Embedded Apple platforms don't support dynamic libraries
if (CMAKE_SYSTEM_NAME MATCHES "^(iOS|tvOS|watchOS|visionOS)$")
    list(APPEND NOD_IMPORT_ARGS CRATE_TYPES staticlib)
endif()
# Import the nod-ffi crate using Corrosion.
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/Cargo.toml"
    CRATES nod-ffi # NOTE: target becomes `nod_ffi`
    ${NOD_IMPORT_ARGS}
)

if (NOD_COMPRESS_BZIP2)
    nod_require_bzip2(_nod_bzip2_target)
    target_link_libraries(nod_ffi INTERFACE "${_nod_bzip2_target}")
    if (TARGET bz2_static)
        corrosion_add_target_local_rustflags(
            nod_ffi
            "-L$<TARGET_LINKER_FILE_DIR:bz2_static>"
            "-lstatic=bz2"
        )
        if (TARGET _cargo-build_nod_ffi)
            add_dependencies(_cargo-build_nod_ffi bz2_static)
        endif()
    else()
        nod_resolve_corrosion_link_input(_nod_bzip2_rust_link "${_nod_bzip2_target}" "bz2")
        corrosion_link_libraries(nod_ffi "${_nod_bzip2_rust_link}")
    endif()
endif()
if (NOD_COMPRESS_LZMA)
    nod_require_liblzma(_nod_liblzma_target)
    target_link_libraries(nod_ffi INTERFACE "${_nod_liblzma_target}")
    nod_resolve_corrosion_link_input(_nod_liblzma_rust_link "${_nod_liblzma_target}" "lzma")
    corrosion_link_libraries(nod_ffi "${_nod_liblzma_rust_link}")
endif()
if (NOD_COMPRESS_ZLIB)
    nod_require_zlib(_nod_zlib_target)
    target_link_libraries(nod_ffi INTERFACE "${_nod_zlib_target}")
    nod_resolve_corrosion_link_input(_nod_zlib_rust_link "${_nod_zlib_target}" "z")
    corrosion_link_libraries(nod_ffi "${_nod_zlib_rust_link}")
endif()
if (NOD_COMPRESS_ZSTD)
    nod_require_zstd(_nod_zstd_target)
    target_link_libraries(nod_ffi INTERFACE "${_nod_zstd_target}")
    nod_resolve_corrosion_link_input(_nod_zstd_rust_link "${_nod_zstd_target}" "zstd")
    corrosion_link_libraries(nod_ffi "${_nod_zstd_rust_link}")
endif()

target_sources(nod_ffi INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include"
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include/nod.h"
)

# Create a namespace alias for the library target.
add_library(nod::nod ALIAS nod_ffi)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    add_subdirectory(nod-ffi/examples)
endif()
