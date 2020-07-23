# main microratchet library files

cmake_minimum_required(VERSION 3.0)

project(libmicroratchet)

set(SOURCES
    aesctr.c
    context_state.c
    context.c
    internal.c
    kdf.c
    pch.c
    ratchet.c
    highlevel.c)

add_library(microratchet STATIC ${SOURCES})


if (DEBUG OR TRACE OR TRACEDATA)
    message(WARNING "This is an insecure build of microratchet")

    if (NOT EMBEDDED)
        target_compile_definitions(microratchet PUBLIC -DMR_WRITE=mr_write_printf)
        target_compile_definitions(microratchet PUBLIC -DMR_WRITE_PRINTF)
    else()
        target_compile_definitions(microratchet PUBLIC -DMR_WRITE=mr_write_uart)
    endif()
endif()


if (DEBUG)
    target_compile_definitions(microratchet PUBLIC -DMR_DEBUG=1)
    target_compile_definitions(microratchet PUBLIC -DMR_ASSERT=assert)
    target_compile_definitions(microratchet PUBLIC -DMR_ABORT=abort)
endif()


if(TRACE)
    target_compile_definitions(microratchet PUBLIC -DMR_TRACE=1)
endif()


if(TRACEDATA)
    target_compile_definitions(microratchet PUBLIC -DMR_TRACE_DATA=1)
endif()