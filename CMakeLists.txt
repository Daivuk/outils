cmake_minimum_required(VERSION 3.0.0)

option(OUTILS_BUILD_TESTS "Generate Unit Tests" OFF)

project(liboutils)

if(WIN32)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

add_library(${PROJECT_NAME} 
    ./src/outils.cpp
    ./src/tinyfiledialogs/tinyfiledialogs.c
    ./include/outils/outils.h
    ./src/json/json_reader.cpp
    ./src/json/json_value.cpp
    ./src/json/json_writer.cpp
)
target_include_directories(${PROJECT_NAME} PUBLIC ./include ./src)

# Disable warnings on some specific thirdparty files
set_source_files_properties("./src/tinyfiledialogs/tinyfiledialogs.c" COMPILE_FLAGS "/wd4267 /wd4244")

if (OUTILS_BUILD_TESTS)
    add_subdirectory(./tests)
endif()
