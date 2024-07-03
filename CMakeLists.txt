cmake_minimum_required(VERSION 3.27)
project(akeneo_file_transfer)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")


if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
endif()

# Find libssh
find_package(LibSSH REQUIRED)
if(NOT LibSSH_FOUND)
    message(FATAL_ERROR "libssh not found")
endif()

# Find ZLIB
find_package(ZLIB REQUIRED)
if(NOT ZLIB_FOUND)
    message(FATAL_ERROR "ZLIB not found")
endif()

find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Add the executable
add_executable(akeneo_file_transfer main.cpp)

# Include directories for libssh and ZLIB
target_include_directories(akeneo_file_transfer PRIVATE
        "/usr/include/libssh"
        ${ZLIB_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(akeneo_file_transfer PRIVATE
        "/root/libssh/build/src/libssh.a" # Build this manually in a static manner
        "/usr/lib/x86_64-linux-gnu/libz.a"
        ${OPENSSL_LIBRARIES}
        -ldl -lpthread
)