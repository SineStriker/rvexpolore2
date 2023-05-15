project(jalr)

add_executable(${PROJECT_NAME} main.c)

target_compile_options(${PROJECT_NAME} PRIVATE -O1)

process_target(${PROJECT_NAME})