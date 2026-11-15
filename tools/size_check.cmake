# cmake -DBIN=file -DLIMIT=bytes -P size_check.cmake
file(SIZE ${BIN} _size)
math(EXPR _pct "${_size} * 100 / ${LIMIT}")
if(_size GREATER LIMIT)
    message(FATAL_ERROR "${BIN} is ${_size} bytes, over the ${LIMIT} byte bootloader region")
endif()
message(STATUS "mimiboot: ${_size} of ${LIMIT} bytes (${_pct}%)")
