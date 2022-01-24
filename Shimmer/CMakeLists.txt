add_public_executable (shimmer shimmer.c)

target_link_libraries (shimmer
	patching cbits ways
	kernel32 user32 psapi
)
