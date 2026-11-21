cmake_minimum_required(VERSION 3.10)
project(Grabber)
set(CMAKE_CXX_STANDARD 17)

find_package(nlohmann_json CONFIG REQUIRED)

add_executable(grabber Main.cpp)

target_link_libraries(grabber PRIVATE winhttp iphlpapi ws2_32 crypt32 nlohmann_json::nlohmann_json)
