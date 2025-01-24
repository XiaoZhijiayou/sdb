
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=/home/li/project/vcpkg/scripts/buildsystems/vcpkg.cmake --fresh
cmake --build . --verbose
cd ..
