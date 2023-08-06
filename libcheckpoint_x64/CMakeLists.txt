project(libcheckpoint_x64)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fomit-frame-pointer")

add_library(checkpoint_x64 SHARED checkpoint.c)