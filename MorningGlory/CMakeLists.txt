file (GLOB morning_headers *.h)
file (GLOB morning_sources *.c)

add_public_library (morning SHARED ${morning_headers} ${morning_sources} morning.def)
target_link_libraries (morning PRIVATE core kernel32)
