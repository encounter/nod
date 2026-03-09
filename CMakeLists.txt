cmake_minimum_required(VERSION 3.23)
project(nod VERSION 2.0.0 LANGUAGES C)

include(FetchContent)

option(NOD_COMPRESS_BZIP2 "Enable BZIP2 support" ON)
option(NOD_COMPRESS_LZMA "Enable LZMA/LZMA2 support" ON)
option(NOD_COMPRESS_ZLIB "Enable zlib/deflate support" ON)
option(NOD_COMPRESS_ZSTD "Enable Zstandard support" ON)
option(NOD_THREADING "Enable threaded processing support" ON)
option(NOD_USE_CMAKE_COMPRESSION
    "Use CMake-provided compression libraries instead of Cargo vendoring. \
When OFF (default), Cargo builds and statically links compression libraries \
via -sys crates. When ON, compression libraries are found/built by CMake \
and linked externally (useful when the parent project shares these libraries)."
    OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Fetch Corrosion, allowing us to import the nod-ffi crate as a CMake target.
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

# Build the feature list based on the selected compression mode.
set(NOD_FEATURES)
if (NOD_USE_CMAKE_COMPRESSION)
    # CMake-provided compression: use base features (raw #[link] FFI).
    # NodCompressionDeps.cmake handles finding/building the C libraries
    # and linking them to the nod_ffi target.
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
else()
    # Cargo-vendored compression (default): -sys crates build and statically
    # link the C libraries within Cargo. No CMake compression deps needed.
    if (NOD_COMPRESS_BZIP2)
        list(APPEND NOD_FEATURES compress-bzip2-static)
    endif()
    if (NOD_COMPRESS_LZMA)
        list(APPEND NOD_FEATURES compress-lzma-static)
    endif()
    if (NOD_COMPRESS_ZLIB)
        list(APPEND NOD_FEATURES compress-zlib-static)
    endif()
    if (NOD_COMPRESS_ZSTD)
        list(APPEND NOD_FEATURES compress-zstd-static)
    endif()
endif()
if (NOD_THREADING)
    list(APPEND NOD_FEATURES threading)
endif()

set(NOD_IMPORT_ARGS NO_DEFAULT_FEATURES)
if (NOD_FEATURES)
    list(APPEND NOD_IMPORT_ARGS FEATURES ${NOD_FEATURES})
endif()
if (DEFINED BUILD_SHARED_LIBS AND NOT BUILD_SHARED_LIBS)
    list(APPEND NOD_IMPORT_ARGS CRATE_TYPES staticlib)
endif()
# Import the nod-ffi crate using Corrosion.
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/Cargo.toml"
    CRATES nod-ffi # NOTE: target becomes `nod_ffi`
    ${NOD_IMPORT_ARGS}
)

# When using CMake-provided compression, find/build the C libraries
# and link them to the Rust target.
if (NOD_USE_CMAKE_COMPRESSION)
    include(NodCompressionDeps)

    if (NOD_COMPRESS_BZIP2)
        nod_require_bzip2(_nod_bzip2_target)
        target_link_libraries(nod_ffi INTERFACE "${_nod_bzip2_target}")
        nod_resolve_corrosion_link_input(_nod_bzip2_rust_link "${_nod_bzip2_target}" "bz2")
        nod_get_target_linker_dir(_nod_bzip2_linker_dir "${_nod_bzip2_rust_link}")
        if (_nod_bzip2_linker_dir)
            corrosion_add_target_rustflags(nod_ffi "-L" "${_nod_bzip2_linker_dir}")
        else()
            corrosion_link_libraries(nod_ffi "${_nod_bzip2_rust_link}")
        endif()
        add_dependencies(_cargo-build_nod_ffi "${_nod_bzip2_rust_link}")
    endif()
    if (NOD_COMPRESS_LZMA)
        nod_require_liblzma(_nod_liblzma_target)
        target_link_libraries(nod_ffi INTERFACE "${_nod_liblzma_target}")
        nod_resolve_corrosion_link_input(_nod_liblzma_rust_link "${_nod_liblzma_target}" "lzma")
        nod_get_target_linker_dir(_nod_liblzma_linker_dir "${_nod_liblzma_rust_link}")
        if (_nod_liblzma_linker_dir)
            corrosion_add_target_rustflags(nod_ffi "-L" "${_nod_liblzma_linker_dir}")
        else()
            corrosion_link_libraries(nod_ffi "${_nod_liblzma_rust_link}")
        endif()
        add_dependencies(_cargo-build_nod_ffi "${_nod_liblzma_rust_link}")
    endif()
    if (NOD_COMPRESS_ZLIB)
        nod_require_zlib(_nod_zlib_target)
        target_link_libraries(nod_ffi INTERFACE "${_nod_zlib_target}")
        nod_resolve_corrosion_link_input(_nod_zlib_rust_link "${_nod_zlib_target}" "z")
        nod_get_target_linker_dir(_nod_zlib_linker_dir "${_nod_zlib_rust_link}")
        if (_nod_zlib_linker_dir)
            corrosion_add_target_rustflags(nod_ffi "-L" "${_nod_zlib_linker_dir}")
        else()
            corrosion_link_libraries(nod_ffi "${_nod_zlib_rust_link}")
        endif()
        add_dependencies(_cargo-build_nod_ffi "${_nod_zlib_rust_link}")
    endif()
    if (NOD_COMPRESS_ZSTD)
        nod_require_zstd(_nod_zstd_target)
        target_link_libraries(nod_ffi INTERFACE "${_nod_zstd_target}")
        nod_resolve_corrosion_link_input(_nod_zstd_rust_link "${_nod_zstd_target}" "zstd")
        nod_get_target_linker_dir(_nod_zstd_linker_dir "${_nod_zstd_rust_link}")
        if (_nod_zstd_linker_dir)
            corrosion_add_target_rustflags(nod_ffi "-L" "${_nod_zstd_linker_dir}")
        else()
            corrosion_link_libraries(nod_ffi "${_nod_zstd_rust_link}")
        endif()
        add_dependencies(_cargo-build_nod_ffi "${_nod_zstd_rust_link}")
    endif()
endif()

target_sources(nod_ffi INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include"
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include/nod.h"
)

# Create a namespace alias for the library target.
add_library(nod::nod ALIAS nod_ffi)

# ── Install ──
include(GNUInstallDirs)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(_NOD_INSTALL_DEFAULT ON)
else ()
    set(_NOD_INSTALL_DEFAULT OFF)
endif ()
option(NOD_ENABLE_INSTALL "Generate install targets" ${_NOD_INSTALL_DEFAULT})

if (NOD_ENABLE_INSTALL)
    # Corrosion's install doesn't generate proper IMPORTED targets for consumers,
    # so we install the library files directly and generate our own CMake config.
    # Rename from nod_ffi to nod.
    install(FILES "$<TARGET_FILE:nod_ffi-shared>"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RENAME "$<PATH:REPLACE_FILENAME,$<TARGET_FILE_NAME:nod_ffi-shared>,${CMAKE_SHARED_LIBRARY_PREFIX}nod${CMAKE_SHARED_LIBRARY_SUFFIX}>"
    )
    install(FILES "$<TARGET_FILE:nod_ffi-static>"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RENAME "$<PATH:REPLACE_FILENAME,$<TARGET_FILE_NAME:nod_ffi-static>,${CMAKE_STATIC_LIBRARY_PREFIX}nod${CMAKE_STATIC_LIBRARY_SUFFIX}>"
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include/nod.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )

    # Generate CMake config files for find_package(nod)
    include(CMakePackageConfigHelpers)
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nodConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/nodConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/nod"
    )
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/nodConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY AnyNewerVersion
    )
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/nodConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/nodConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/nod"
    )
endif()

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    add_subdirectory(nod-ffi/examples)
endif()
