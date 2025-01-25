# 编译为位置无关可执行文件（PIE）
# PIE：就是在编译时，生成的可执行文件中的代码段是可重定位的，即可以在内存中的任意位置加载执行
function(add_test_cpp_target  name)
    add_executable(${name} "${name}.cpp")
    target_compile_options(${name} PRIVATE -g -O0 -pie)
    add_dependencies(tests ${name})
endfunction()
    
function(add_test_asm_target name)
    add_executable(${name} "${name}.s")
    target_compile_options(${name} PRIVATE -g -O0 -pie)
    add_dependencies(tests ${name})
    
endfunction()

add_test_cpp_target(run_endlessly)
add_test_cpp_target(end_immediately)
add_test_cpp_target(hello_sdb)
add_test_asm_target(reg_write)
add_test_asm_target(reg_read)

