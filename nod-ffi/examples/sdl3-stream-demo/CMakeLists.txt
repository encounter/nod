cmake_minimum_required(VERSION 3.23)
project(nod_sdl3_stream_demo C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT TARGET SDL3::SDL3)
    find_package(SDL3 REQUIRED CONFIG)
endif()

add_executable(nod_sdl3_stream_demo main.c)
target_link_libraries(nod_sdl3_stream_demo PRIVATE SDL3::SDL3 nod::nod)
