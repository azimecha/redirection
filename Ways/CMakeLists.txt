file (GLOB ways_headers *.h)
file (GLOB ways_exported_headers Exported/*.h)
file (GLOB ways_sources *.c)

add_public_library (ways SHARED 
	${ways_headers}
	${ways_exported_headers} 
	${ways_sources} 
	ways.def
)

target_link_libraries (ways PRIVATE
	core patching
	kernel32 psapi
)

target_include_directories (ways PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Exported)
target_compile_definitions (ways PRIVATE MAGICWAYS_BUILD)
