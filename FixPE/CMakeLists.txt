add_executable (fixpe fixpe.c)
target_link_libraries (fixpe kernel32 user32 core coreplus)
