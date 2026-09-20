cmake_minimum_required(VERSION 3.23)
project(nod VERSION 2.0.0 LANGUAGES C)

include(FetchContent)

option(NOD_COMPRESS_BZIP2 "Enable BZIP2 support" ON)
option(NOD_COMPRESS_LZMA "Enable LZMA/LZMA2 support" ON)
option(NOD_COMPRESS_ZLIB "Enable zlib/deflate support" ON)
option(NOD_COMPRESS_ZSTD "Enable Zstandard support" ON)
option(NOD_THREADING "Enable threaded processing support" ON)
# Retained for compatibility with existing parent projects. All codecs are now
# compiled from Rust by Cargo, so no external compression libraries are needed.
option(NOD_USE_CMAKE_COMPRESSION "Compatibility option (compression is pure Rust)" OFF)

# Fetch Corrosion, allowing us to import the nod-ffi crate as a CMake target.
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

# The feature names and toggles are unchanged; each codec now uses pure Rust.
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
if (DEFINED BUILD_SHARED_LIBS AND NOT BUILD_SHARED_LIBS)
    list(APPEND NOD_IMPORT_ARGS CRATE_TYPES staticlib)
endif()
# Import the nod-ffi crate using Corrosion.
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/Cargo.toml"
    CRATES nod-ffi # NOTE: target becomes `nod`
    ${NOD_IMPORT_ARGS}
)

target_sources(nod INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include"
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include/nod.h"
)

# Create a namespace alias for the library target.
add_library(nod::nod ALIAS nod)

# Install
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

    # Shared library
    if (TARGET nod-shared)
        if (WIN32)
            # DLL to bin/
            install(FILES "$<TARGET_FILE:nod-shared>"
                DESTINATION "${CMAKE_INSTALL_BINDIR}"
                RENAME "${CMAKE_SHARED_LIBRARY_PREFIX}nod${CMAKE_SHARED_LIBRARY_SUFFIX}"
            )
            # Import library to lib/
            install(FILES "$<TARGET_LINKER_FILE:nod-shared>"
                DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                RENAME "${CMAKE_IMPORT_LIBRARY_PREFIX}nod${CMAKE_IMPORT_LIBRARY_SUFFIX}"
            )
        else()
            install(FILES "$<TARGET_FILE:nod-shared>"
                DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                RENAME "${CMAKE_SHARED_LIBRARY_PREFIX}nod${CMAKE_SHARED_LIBRARY_SUFFIX}"
            )
        endif()
    endif()

    # Static library
    if (TARGET nod-static)
        if (MSVC)
            # On MSVC, use nod_static to avoid collision with the DLL import library
            set(_nod_static_name "nod_static${CMAKE_STATIC_LIBRARY_SUFFIX}")
        else()
            set(_nod_static_name "${CMAKE_STATIC_LIBRARY_PREFIX}nod${CMAKE_STATIC_LIBRARY_SUFFIX}")
        endif()
        install(FILES "$<TARGET_FILE:nod-static>"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            RENAME "${_nod_static_name}"
        )
    endif()

    # Header
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/nod-ffi/include/nod.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )

    # Generate CMake config files for find_package(nod)
    include(CMakePackageConfigHelpers)
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nodConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/nodConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/nod"
        PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_BINDIR
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
