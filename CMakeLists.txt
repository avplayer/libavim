cmake_minimum_required(VERSION 2.8.9)

project(libavprotocol)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library( avprotocol STATIC src/avkernel.cpp src/avif.cpp src/avtcpif.cpp)

add_library( avprotocolC SHARED src/avC_stub.cpp)
target_link_libraries( avprotocolC avprotocol)
