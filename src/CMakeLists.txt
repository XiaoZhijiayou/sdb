add_library(libsdb process.cpp pipe.cpp registers.cpp breakpoint_site.cpp disassembler.cpp watchpoint.cpp) 
add_library(sdb::libsdb ALIAS libsdb)
target_link_libraries(libsdb PRIVATE Zydis::Zydis)

set_target_properties(
    libsdb
    PROPERTIES OUTPUT_NAME sdb
)

target_compile_features(libsdb PUBLIC cxx_std_17)

# 指定libsdb的包含目录，告诉CMake在编译时包含哪些头文件
# private : 目录是 私有的，这意味着只有 libsdb 目标会使用这个目录中的头文件
#           如果其他目标链接到 libsdb，它们不会继承这个包含路径。
# public: 相反的意思
# target_include_directories(
#     libsdb
#     PRIVATE include
#     PUBLIC ${CMAKE_SOURCE_DIR}/include
# )

# PUBLIC $<INSTALL_INTERFACE:include>
# : 当你将 libsdb 库 安装 到你的电脑上时，这一行告诉 CMake：安装后，
#   用户使用 libsdb 库时，要从哪个目录找到它的头文件。

# PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
# :告诉 CMake，在 构建 libsdb 库时，头文件应该放在哪个目录。
#  CMAKE_SOURCE_DIR 是指你的项目的根目录
# 所以，构建 libsdb 库时，CMake 会在 项目根目录下的 include 文件夹里查找头文件。

target_include_directories(libsdb
    PUBLIC
      $<INSTALL_INTERFACE:include>
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/include
)

include(GNUInstallDirs)
install(TARGETS libsdb
        EXPORT sdb-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEIR}
)

install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT sdb-targets
    FILE sdb-config.cmake
    NAMESPACE sdb::
    DESTINATION ${CMKAE_INSTALL_LIBDIR}/cmake/sdb
)
