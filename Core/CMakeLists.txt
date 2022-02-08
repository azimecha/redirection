file (GLOB_RECURSE core_headers *.h)
file (GLOB_RECURSE core_sources *.c)
add_library (core STATIC ${core_headers} ${core_sources})
target_include_directories (core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})