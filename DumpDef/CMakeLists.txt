add_executable (dumpdef dumpdef.c)
target_link_libraries (dumpdef kernel32 user32 cbits)
