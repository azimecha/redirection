add_redir_dll (advapi_r advapi32 ../dllmain.c)
target_link_libraries (advapi_r PRIVATE core kernel32 user32)
