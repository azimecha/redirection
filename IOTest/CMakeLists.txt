add_executable (iotest IOTest.c)
target_link_libraries (iotest kernel32 user32 core coreplus ways)
