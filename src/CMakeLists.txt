function(process_target _target)
    set(options GENERATE)
    set(oneValueArgs)
    set(multiValueArgs)
    cmake_parse_arguments(FUNC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    target_compile_options(${_target} PRIVATE -fno-stack-protector)
    set(_file $<TARGET_FILE_DIR:${_target}>/$<TARGET_FILE_BASE_NAME:${_target}>.S)
    set(_rvc_file ${CMAKE_CURRENT_BINARY_DIR}/rvc_${_target}.cpp)
    set(_binary_data_file ${CMAKE_CURRENT_BINARY_DIR}/binary_data.h)

    if(FUNC_GENERATE)
        add_custom_command(TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_C_COMPILER} -fno-stack-protector -nostdlib -nodefaultlibs -nostartfiles -no-pie -e main -O3 -I${RVEXPLORE_INCLUDE_DIR}
            $<TARGET_PROPERTY:${_target},SOURCES> -o $<TARGET_FILE_DIR:${_target}>/$<TARGET_FILE_NAME:${_target}>.elf
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

        add_custom_command(TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_OBJDUMP} -d $<TARGET_FILE_NAME:${_target}>.elf > $<TARGET_FILE_BASE_NAME:${_target}>.elf.S
            COMMAND ${CMAKE_OBJCOPY} -S $<TARGET_FILE_NAME:${_target}>.elf -O binary
            -R .note.gnu.property -R .note.gnu.build-id -R .comment $<TARGET_FILE_NAME:${_target}>.bin

            COMMAND ${Python_EXECUTABLE} ${RVEXPLORE_SCRIPTS_DIR}/rvc.py $<TARGET_FILE_NAME:${_target}>.bin
            --out ${_rvc_file} --native-call
            --entry "$$(" ${CMAKE_OBJDUMP} -f $<TARGET_FILE_NAME:${_target}>.elf | grep "start address" | cut -d " " -f "3)"

            COMMAND ${Python_EXECUTABLE} ${RVEXPLORE_SCRIPTS_DIR}/gen_gdb_script.py $<TARGET_FILE_NAME:${_target}>.bin
            --out $<TARGET_FILE_BASE_NAME:${_target}>_jmp.gdb

            WORKING_DIRECTORY $<TARGET_FILE_DIR:${_target}>
        )

        add_custom_command(TARGET ${_target} POST_BUILD
            COMMAND $<TARGET_FILE:bintoh++> $<TARGET_FILE_NAME:${_target}>.bin ${_binary_data_file}
            WORKING_DIRECTORY $<TARGET_FILE_DIR:${_target}>
        )

        file(WRITE ${_rvc_file} "// blank")
        file(WRITE ${_binary_data_file} "const unsigned char binary_data[] = \"1\";")

        target_sources(toy PRIVATE ${_rvc_file})
        target_include_directories(toy PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        add_dependencies(toy ${_target})
    endif()

    add_custom_command(TARGET ${_target} POST_BUILD
        COMMAND ${CMAKE_OBJDUMP} -d "$<TARGET_FILE:${_target}>" > ${_file}
    )
endfunction()

set(RVEXPLORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories(include)

add_subdirectory(bintoh++)

add_subdirectory(toy)

add_subdirectory(algos)