cmake_minimum_required(VERSION 3.23)
project(nod C)

include(FetchContent)

option(NOD_COMPRESS_BZIP2 "Enable BZIP2 support" ON)
option(NOD_COMPRESS_LZMA "Enable LZMA/LZMA2 support" ON)
option(NOD_COMPRESS_ZLIB "Enable zlib/deflate support" ON)
option(NOD_COMPRESS_ZSTD "Enable Zstandard support" ON)
option(NOD_THREADING "Enable threaded processing support" ON)

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

# Import the nod-ffi crate using Corrosion.
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/Cargo.toml"
    CRATES nod-ffi # NOTE: target becomes `nod_ffi`
    ${NOD_IMPORT_ARGS}
)

if (NOD_COMPRESS_BZIP2)
    if (NOT TARGET BZip2::BZip2)
        find_package(BZip2 REQUIRED)
    endif()
    target_link_libraries(nod_ffi INTERFACE BZip2::BZip2)
endif()
if (NOD_COMPRESS_LZMA)
    if (NOT TARGET LibLZMA::LibLZMA)
        find_package(LibLZMA REQUIRED)
    endif()
    target_link_libraries(nod_ffi INTERFACE LibLZMA::LibLZMA)
endif()
if (NOD_COMPRESS_ZLIB)
    if (NOT TARGET ZLIB::ZLIB)
        find_package(ZLIB REQUIRED)
    endif()
    target_link_libraries(nod_ffi INTERFACE ZLIB::ZLIB)
endif()
if (NOD_COMPRESS_ZSTD)
    if (TARGET libzstd)
        target_link_libraries(nod_ffi INTERFACE libzstd)
    else()
        if (NOT TARGET PkgConfig::LIBZSTD)
            find_package(PkgConfig REQUIRED)
            pkg_check_modules(LIBZSTD REQUIRED IMPORTED_TARGET libzstd)
        endif()
        target_link_libraries(nod_ffi INTERFACE PkgConfig::LIBZSTD)
    endif()
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
