#pragma once

#ifndef HEADER_WAYSDEF
#define HEADER_WAYSDEF

#ifndef MAGICWAYS_EXPORTED
#ifdef MAGICWAYS_BUILD
#define MAGICWAYS_EXPORTED __declspec(dllexport) __stdcall
#else
#define MAGICWAYS_EXPORTED __declspec(dllimport) __stdcall
#endif
#endif

#define _X86_
#include <minwindef.h>

#endif
