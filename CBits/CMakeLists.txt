file (GLOB_RECURSE cbits_headers *.h)
file (GLOB_RECURSE cbits_sources *.c)
add_library (cbits STATIC ${cbits_headers} ${cbits_sources})
target_include_directories (cbits PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})