cmake_minimum_required(VERSION 3.23)
project(nod_ffi_examples C)

find_package(SDL3 QUIET CONFIG)
if(TARGET SDL3::SDL3)
    add_subdirectory(sdl3-stream-demo)
else()
    message(STATUS "SDL3 not found; skipping sdl3-stream-demo example")
endif()
