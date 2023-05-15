cmake_minimum_required(VERSION 3.17)

project(rvexplore2 LANGUAGES C)

# Find python
find_package(Python REQUIRED)

if(Python_FOUND)
    message(STATUS "Python found: ${Python_EXECUTABLE}")
endif()

# Find toolchain tools
if(CMAKE_OBJCOPY)
    message(STATUS "Objcopy found: ${CMAKE_OBJCOPY}")
endif()

if(CMAKE_OBJDUMP)
    message(STATUS "Objdump found: ${CMAKE_OBJDUMP}")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(RVEXPLORE_SCRIPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/scripts)

add_subdirectory(src)