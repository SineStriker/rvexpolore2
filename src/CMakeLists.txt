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
    endif()

    add_custom_command(TARGET ${_target} POST_BUILD
        COMMAND ${CMAKE_OBJDUMP} -d "$<TARGET_FILE:${_target}>" > ${_file}
        ${_extra_command}
    )
endfunction()

add_subdirectory(algos)