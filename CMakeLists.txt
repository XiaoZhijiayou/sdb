cmake_minimum_required(VERSION 3.19)

project("sdb" LANGUAGES CXX ASM)

message(STATUS "CMake Toolchain File: ${CMAKE_TOOLCHAIN_FILE}")



find_package(PkgConfig REQUIRED)

pkg_check_modules(readline REQUIRED IMPORTED_TARGET readline)
find_package(fmt CONFIG REQUIRED)
find_package(zydis CONFIG REQUIRED)
include(CTest)

# 这行将 src 目录添加到 CMake 构建过程中，
# 意味着 CMake 会进入 src 目录，
#寻找并执行 src/CMakeLists.txt 中的构建规则
add_subdirectory("src")
add_subdirectory("tools")

if(BUILD_TESTING)
    find_package(Catch2 CONFIG REQUIRED)    
    add_subdirectory("test")
endif()


