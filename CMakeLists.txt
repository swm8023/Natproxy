cmake_minimum_required(VERSION 2.8.9)
project(libfastnet C CXX)


set(DEBUG  false)



if (DEBUG)
    set(CMAKE_BUILD_TYPE DEBUG)
	add_definitions(-DDEBUG)
    add_compile_options(-g -O0)
else()
    add_definitions(-DNDEBUG)
    add_compile_options(-O2)
endif()

include_directories(include)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)


set(extra_libs
	oh m pthread
)

link_directories(${PROJECT_SOURCE_DIR}/lib)

add_executable(npclient src/natproxyclient.c)
target_link_libraries(npclient ${extra_libs})

add_executable(npserver src/natproxyserver.c)
target_link_libraries(npserver ${extra_libs})