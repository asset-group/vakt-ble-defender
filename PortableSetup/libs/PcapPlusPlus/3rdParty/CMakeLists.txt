cmake_minimum_required(VERSION 3.22.1)

add_subdirectory(EndianPortable)
add_subdirectory(LightPcapNg)

if(PCAPPP_BUILD_TESTS)
    add_subdirectory(debug-new)
endif()
