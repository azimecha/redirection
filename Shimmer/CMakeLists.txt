add_executable (shimmer shimmer.c)
target_link_libraries (shimmer kernel32 user32 cbits psapi)
