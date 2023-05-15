function(process_target _target)
    set(options GENERATE)
    set(oneValueArgs)
    set(multiValueArgs)
    cmake_parse_arguments(FUNC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    target_compile_options(${_target} PRIVATE -fno-stack-protector)
    set(_file $<TARGET_FILE_DIR:${_target}>/$<TARGET_FILE_BASE_NAME:${_target}>.S)
    set(_rvc_file ${CMAKE_CURRENT_BINARY_DIR}/rvc_$<TARGET_FILE_BASE_NAME:${_target}>.c)

    if(FUNC_GENERATE)
        set(_extra_command COMMAND ${Python_EXECUTABLE} ${RVEXPLORE_SCRIPTS_DIR}/rvc.py ${_file} --out ${_rvc_file})
        add_custom_command(TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_C_COMPILER} -fno-stack-protector -nostdlib -nodefaultlibs -nostartfiles -no-pie -e main -O3 -I${RVEXPLORE_INCLUDE_DIR}
            $<TARGET_PROPERTY:${_target},SOURCES> -o $<TARGET_FILE_DIR:${_target}>/$<TARGET_FILE_NAME:${_target}>.elf
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        add_custom_command(TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_OBJDUMP} -d $<TARGET_FILE_NAME:${_target}>.elf > $<TARGET_FILE_BASE_NAME:${_target}>.elf.S
            COMMAND ${CMAKE_OBJCOPY} -S $<TARGET_FILE_NAME:${_target}>.elf -O binary -R .note.gnu.property -R .note.gnu.build-id -R .comment $<TARGET_FILE_NAME:${_target}>.bin
            WORKING_DIRECTORY $<TARGET_FILE_DIR:${_target}>
        )
    endif()

    add_custom_command(TARGET ${_target} POST_BUILD
        COMMAND ${CMAKE_OBJDUMP} -d "$<TARGET_FILE:${_target}>" > ${_file}
        ${_extra_command}
    )
endfunction()

set(RVEXPLORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories(include)

add_subdirectory(algos)