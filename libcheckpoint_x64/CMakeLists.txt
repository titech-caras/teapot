project(libcheckpoint_x64)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_library(checkpoint_x64 checkpoint.c)