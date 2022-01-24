file (GLOB ways_headers *.h)
file (GLOB ways_sources *.c)

add_public_library (ways SHARED ${ways_headers} ${ways_sources} ways.def)

target_link_libraries (ways PRIVATE
	cbits patching
	kernel32 psapi
)
