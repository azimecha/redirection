add_library (ways SHARED IDLLMain.c Intercept.c Intercept.h ways.def)

target_link_libraries (ways PRIVATE
	cbits patching
	kernel32 psapi
)
