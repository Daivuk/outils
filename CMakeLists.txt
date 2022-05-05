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
)
target_include_directories(${PROJECT_NAME} PUBLIC ./include ./src)

if (OUTILS_BUILD_TESTS)
    add_subdirectory(./tests)
endif()
