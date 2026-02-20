include_guard(GLOBAL)

include(FetchContent)

set(NOD_ZLIB_GIT_TAG "v1.3.2") # https://github.com/madler/zlib
set(NOD_ZSTD_GIT_TAG "v1.5.7") # https://github.com/facebook/zstd
set(NOD_XZ_GIT_TAG "v5.8.2") # https://github.com/tukaani-project/xz
set(NOD_BZIP2_GIT_TAG "66c46b8c9436613fd81bc5d03f63a61933a4dcc3") # https://gitlab.com/bzip2/bzip2

function(nod_first_available_target out_var)
    foreach(_candidate IN LISTS ARGN)
        if (TARGET "${_candidate}")
            set("${out_var}" "${_candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set("${out_var}" "" PARENT_SCOPE)
endfunction()

function(nod_bind_interface_target interface_target implementation_target)
    if (NOT TARGET "${interface_target}")
        add_library("${interface_target}" INTERFACE IMPORTED GLOBAL)
        set_target_properties(
            "${interface_target}"
            PROPERTIES INTERFACE_LINK_LIBRARIES "${implementation_target}"
        )
    endif()
endfunction()

# Corrosion's target-based rustflags path uses TARGET_LINKER_FILE_BASE_NAME,
# which can produce invalid names for imported namespaced targets. For imported
# targets, create a local imported wrapper with a controlled OUTPUT_NAME.
function(nod_resolve_corrosion_link_input out_var input_link rust_link_name)
    if (TARGET "${input_link}")
        get_target_property(_imported "${input_link}" IMPORTED)
        if (_imported)
            set(_loc "")
            foreach(_prop
                IMPORTED_LOCATION
                IMPORTED_LOCATION_RELEASE
                IMPORTED_LOCATION_RELWITHDEBINFO
                IMPORTED_LOCATION_MINSIZEREL
                IMPORTED_LOCATION_DEBUG
                IMPORTED_IMPLIB
                IMPORTED_IMPLIB_RELEASE
                IMPORTED_IMPLIB_RELWITHDEBINFO
                IMPORTED_IMPLIB_MINSIZEREL
                IMPORTED_IMPLIB_DEBUG
                LOCATION
            )
                get_target_property(_loc "${input_link}" "${_prop}")
                if (_loc AND IS_ABSOLUTE "${_loc}")
                    break()
                endif()
            endforeach()
            if (_loc AND IS_ABSOLUTE "${_loc}")
                # Derive OUTPUT_NAME from the actual filename to ensure
                # the correct -l flag is passed on all platforms.
                # (e.g. zlib.lib on MSVC vs libz.a on Unix)
                get_filename_component(_stem "${_loc}" NAME_WE)
                if (NOT MSVC AND _stem MATCHES "^lib(.+)$")
                    set(_stem "${CMAKE_MATCH_1}")
                endif()
                set(_wrapper_target "nod_corrosion_link_${rust_link_name}")
                if (NOT TARGET "${_wrapper_target}")
                    add_library("${_wrapper_target}" UNKNOWN IMPORTED GLOBAL)
                endif()
                set_target_properties(
                    "${_wrapper_target}"
                    PROPERTIES
                        IMPORTED_LOCATION "${_loc}"
                        OUTPUT_NAME "${_stem}"
                )
                set("${out_var}" "${_wrapper_target}" PARENT_SCOPE)
                return()
            endif()
        endif()
    endif()
    set("${out_var}" "${input_link}" PARENT_SCOPE)
endfunction()

function(nod_require_bzip2 out_target)
    nod_first_available_target(_bzip2_target bz2_static bz2 BZip2::BZip2)
    if (_bzip2_target)
        if (NOT TARGET BZip2::BZip2)
            nod_bind_interface_target(BZip2::BZip2 "${_bzip2_target}")
        endif()
        set("${out_target}" "${_bzip2_target}" PARENT_SCOPE)
        return()
    endif()

    # To force vendoring from the CLI, pass: -DCMAKE_DISABLE_FIND_PACKAGE_BZip2=ON
    find_package(BZip2 QUIET)
    nod_first_available_target(_bzip2_target bz2_static bz2 BZip2::BZip2)
    if (_bzip2_target)
        set("${out_target}" "${_bzip2_target}" PARENT_SCOPE)
        return()
    endif()

    message(STATUS "BZip2 not found; fetching bzip2 ${NOD_BZIP2_GIT_TAG}")
    set(ENABLE_LIB_ONLY ON CACHE INTERNAL "")
    set(ENABLE_APP OFF CACHE INTERNAL "")
    set(ENABLE_TESTS OFF CACHE INTERNAL "")
    set(ENABLE_DOCS OFF CACHE INTERNAL "")
    set(ENABLE_EXAMPLES OFF CACHE INTERNAL "")
    set(ENABLE_SHARED_LIB OFF CACHE INTERNAL "")
    set(ENABLE_STATIC_LIB ON CACHE INTERNAL "")
    FetchContent_Declare(
        nod_bzip2
        GIT_REPOSITORY https://gitlab.com/bzip2/bzip2.git
        GIT_TAG "${NOD_BZIP2_GIT_TAG}"
    )
    FetchContent_MakeAvailable(nod_bzip2)
    if (TARGET bz2_static)
        # Make the static archive name match `#[link(name = "bz2")]` in Rust.
        set_target_properties(
            bz2_static
            PROPERTIES
                OUTPUT_NAME bz2
                ARCHIVE_OUTPUT_NAME bz2
        )
    endif()
    nod_first_available_target(_bzip2_target bz2_static bz2 BZip2::BZip2)
    if (NOT _bzip2_target)
        message(FATAL_ERROR "Unable to provide a usable BZip2 target after vendoring bzip2")
    endif()
    if (NOT TARGET BZip2::BZip2)
        nod_bind_interface_target(BZip2::BZip2 "${_bzip2_target}")
    endif()
    set("${out_target}" "${_bzip2_target}" PARENT_SCOPE)
endfunction()

function(nod_require_liblzma out_target)
    nod_first_available_target(_lzma_target liblzma liblzma::liblzma LibLZMA::LibLZMA)
    if (_lzma_target)
        if (NOT TARGET LibLZMA::LibLZMA)
            nod_bind_interface_target(LibLZMA::LibLZMA "${_lzma_target}")
        endif()
        set("${out_target}" "${_lzma_target}" PARENT_SCOPE)
        return()
    endif()

    # To force vendoring from the CLI, pass: -DCMAKE_DISABLE_FIND_PACKAGE_LibLZMA=ON
    find_package(LibLZMA QUIET)
    nod_first_available_target(_lzma_target liblzma liblzma::liblzma LibLZMA::LibLZMA)
    if (_lzma_target)
        if (NOT TARGET LibLZMA::LibLZMA)
            nod_bind_interface_target(LibLZMA::LibLZMA "${_lzma_target}")
        endif()
        set("${out_target}" "${_lzma_target}" PARENT_SCOPE)
        return()
    endif()

    message(STATUS "LibLZMA not found; fetching xz ${NOD_XZ_GIT_TAG}")
    set(XZ_NLS OFF CACHE INTERNAL "")
    set(XZ_DOC OFF CACHE INTERNAL "")
    set(XZ_DOXYGEN OFF CACHE INTERNAL "")
    set(XZ_TOOL_XZ OFF CACHE INTERNAL "")
    set(XZ_TOOL_XZDEC OFF CACHE INTERNAL "")
    set(XZ_TOOL_LZMADEC OFF CACHE INTERNAL "")
    set(XZ_TOOL_LZMAINFO OFF CACHE INTERNAL "")
    set(XZ_TOOL_SCRIPTS OFF CACHE INTERNAL "")
    FetchContent_Declare(
        nod_xz
        GIT_REPOSITORY https://github.com/tukaani-project/xz.git
        GIT_TAG "${NOD_XZ_GIT_TAG}"
    )
    FetchContent_MakeAvailable(nod_xz)

    if (TARGET liblzma AND NOT TARGET liblzma::liblzma)
        nod_bind_interface_target(liblzma::liblzma liblzma)
    endif()
    if (TARGET liblzma::liblzma AND NOT TARGET LibLZMA::LibLZMA)
        nod_bind_interface_target(LibLZMA::LibLZMA liblzma::liblzma)
    endif()
    nod_first_available_target(_lzma_target liblzma liblzma::liblzma LibLZMA::LibLZMA)
    if (NOT _lzma_target)
        message(FATAL_ERROR "Unable to provide a usable LibLZMA target after vendoring xz")
    endif()
    if (NOT TARGET LibLZMA::LibLZMA)
        nod_bind_interface_target(LibLZMA::LibLZMA "${_lzma_target}")
    endif()
    set("${out_target}" "${_lzma_target}" PARENT_SCOPE)
endfunction()

function(nod_require_zlib out_target)
    nod_first_available_target(_zlib_target zlib zlibstatic ZLIB::ZLIB)
    if (_zlib_target)
        if (NOT TARGET ZLIB::ZLIB)
            nod_bind_interface_target(ZLIB::ZLIB "${_zlib_target}")
        endif()
        set("${out_target}" "${_zlib_target}" PARENT_SCOPE)
        return()
    endif()

    # To force vendoring from the CLI, pass: -DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=ON
    find_package(ZLIB QUIET)
    nod_first_available_target(_zlib_target zlib zlibstatic ZLIB::ZLIB)
    if (_zlib_target)
        if (NOT TARGET ZLIB::ZLIB)
            nod_bind_interface_target(ZLIB::ZLIB "${_zlib_target}")
        endif()
        set("${out_target}" "${_zlib_target}" PARENT_SCOPE)
        return()
    endif()

    message(STATUS "ZLIB not found; fetching zlib ${NOD_ZLIB_GIT_TAG}")
    set(ZLIB_BUILD_TESTING OFF CACHE INTERNAL "")
    set(ZLIB_INSTALL OFF CACHE INTERNAL "")
    FetchContent_Declare(
        nod_zlib
        GIT_REPOSITORY https://github.com/madler/zlib.git
        GIT_TAG "${NOD_ZLIB_GIT_TAG}"
    )
    FetchContent_MakeAvailable(nod_zlib)

    nod_first_available_target(_zlib_target zlib zlibstatic ZLIB::ZLIB)
    if (NOT _zlib_target)
        message(FATAL_ERROR "Unable to provide a usable ZLIB target after vendoring zlib")
    endif()
    if (NOT TARGET ZLIB::ZLIB)
        nod_bind_interface_target(ZLIB::ZLIB "${_zlib_target}")
    endif()
    set("${out_target}" "${_zlib_target}" PARENT_SCOPE)
endfunction()

function(nod_require_zstd out_target)
    nod_first_available_target(
        _zstd_target
        libzstd_static
        libzstd_shared
        zstd::libzstd_static
        zstd::libzstd_shared
        libzstd
        zstd::libzstd
    )
    if (_zstd_target)
        set("${out_target}" "${_zstd_target}" PARENT_SCOPE)
        return()
    endif()

    # To force vendoring from the CLI, pass: -DCMAKE_DISABLE_FIND_PACKAGE_zstd=ON
    find_package(zstd QUIET)
    nod_first_available_target(
        _zstd_target
        libzstd_static
        libzstd_shared
        zstd::libzstd_static
        zstd::libzstd_shared
        libzstd
        zstd::libzstd
    )
    if (_zstd_target)
        set("${out_target}" "${_zstd_target}" PARENT_SCOPE)
        return()
    endif()

    message(STATUS "Zstandard not found; fetching zstd ${NOD_ZSTD_GIT_TAG}")
    set(ZSTD_BUILD_PROGRAMS OFF CACHE INTERNAL "")
    set(ZSTD_BUILD_TESTS OFF CACHE INTERNAL "")
    set(ZSTD_BUILD_CONTRIB OFF CACHE INTERNAL "")
    FetchContent_Declare(
        nod_zstd
        GIT_REPOSITORY https://github.com/facebook/zstd.git
        GIT_TAG "${NOD_ZSTD_GIT_TAG}"
        SOURCE_SUBDIR build/cmake
    )
    FetchContent_MakeAvailable(nod_zstd)

    nod_first_available_target(
        _zstd_target
        libzstd_static
        libzstd_shared
        zstd::libzstd_static
        zstd::libzstd_shared
        libzstd
        zstd::libzstd
    )
    if (NOT _zstd_target)
        message(FATAL_ERROR "Unable to provide a usable zstd target after vendoring zstd")
    endif()
    set("${out_target}" "${_zstd_target}" PARENT_SCOPE)
endfunction()
