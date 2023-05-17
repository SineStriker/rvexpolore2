project(toy)

add_executable(${PROJECT_NAME} main.cpp common.h jump_table.h)

target_include_directories(${PROJECT_NAME} PRIVATE .)

target_compile_options(toy PRIVATE -g)