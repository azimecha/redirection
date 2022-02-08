add_redir_dll (kernel_r kernel32 ../dllmain.c)
target_link_libraries (kernel_r PRIVATE core user32)
