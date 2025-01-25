sudo rm -rf build && mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=/home/li/project/vcpkg/scripts/buildsystems/vcpkg.cmake -G Ninja ..
cmake --build . --verbose
./test/tests
cd ..

