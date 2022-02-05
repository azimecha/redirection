cmake_minimum_required (VERSION 3.0)
project (MagicWays)

function (target_import_def tgt_name def_path)
	get_filename_component (def_name "${def_path}" NAME_WE)
	set (lib_path "${CMAKE_CURRENT_BINARY_DIR}/${tgt_name}_${def_name}_imp.lib")
	add_custom_command (
		TARGET ${tgt_name} PRE_BUILD
		COMMAND lib "/def:${def_path}" "/out:${lib_path}" /machine:x86 /nodefaultlib
		DEPENDS "${def_path}"
		VERBATIM
		COMMENT "Generating ${lib_path} from DEF file ${def_path}"
	)
	target_link_libraries (${tgt_name} PRIVATE "${lib_path}")
endfunction ()

function (target_fix_pe tgt_name)
	add_custom_command (TARGET ${tgt_name} POST_BUILD
		COMMAND fixpe "$<TARGET_FILE:${tgt_name}>"
		VERBATIM
		DEPENDS fixpe
		COMMENT "Fixing any PE file issues with ${tgt_name}"
	)
endfunction ()

function (add_public_executable tgt_name)
	add_executable (${tgt_name} ${ARGN})
	target_fix_pe (${tgt_name})
endfunction ()

function (add_public_library tgt_name)
	add_library (${tgt_name} ${ARGN})
	target_fix_pe (${tgt_name})
endfunction ()

function (add_redir_dll dll_name orig_name)
	file (GLOB dll_headers *.h)
	file (GLOB dll_sources *.c)
	
	add_public_library (${dll_name} SHARED ${dll_name}.def ${dll_headers} ${dll_sources} ${ARGN})
	target_link_options (${dll_name} PRIVATE /nodefaultlib:${orig_name}.lib)
	target_import_def (${dll_name} ${CMAKE_CURRENT_SOURCE_DIR}/${orig_name}.def)
	target_link_libraries (${dll_name} PRIVATE ways)
endfunction ()

if (MSVC)
	set (CMAKE_CXX_STANDARD_LIBRARIES "")
	set (CMAKE_C_STANDARD_LIBRARIES "")
	
	add_link_options (/nodefaultlib /entry:EntryMSVC /map)
	add_compile_options (/wd28251 /MT /GS- /Oi-)
	
	add_definitions (
		/D_NO_CRT_STDIO_INLINE
		/DENTRY_POINT=EntryMSVC 
		/D_CRT_SECURE_NO_WARNINGS
		/D_CRT_SEUCRE_NO_DEPRECATE
	)
	
	string (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	string (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
	string (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
	string (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
else ()
	message (ERROR "Unknown compiler ${CMAKE_C_COMPILER_ID}!")
endif ()

add_definitions (
	/D_WIN32_WINNT=0x0501
	/DWINVER=0x0501
)

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Output/Unspecified)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Output/Unspecified)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Output/Unspecified)
set (CMAKE_PDB_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Output/Unspecified)

foreach (OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string (TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/Output/${OUTPUTCONFIG})
    set (CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/Output/${OUTPUTCONFIG})
    set (CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/Output/${OUTPUTCONFIG})
    set (CMAKE_PDB_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/Output/${OUTPUTCONFIG})
endforeach (OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES)

add_subdirectory (CBits)
add_subdirectory (Patching)
add_subdirectory (DumpDef)
add_subdirectory (FixPE)
add_subdirectory (Shimmer)
add_subdirectory (Interceptor)
add_subdirectory (ProcessEntry)
add_subdirectory (Kernel32)
add_subdirectory (User32)
add_subdirectory (AdvAPI32)