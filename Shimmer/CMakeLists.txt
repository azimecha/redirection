add_public_executable (shimmer shimmer.c)

target_link_libraries (shimmer
	patching core coreplus ways
	kernel32 user32 psapi
)
