/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/* Is not x64? */
#ifndef _WIN64
	/* Include x86 dissasembler */
	#include "hde/hde32.h"
	/* Force common name */
	typedef hde32s HDE;
	/* Force common func */
	#define HDE_DISASM( code, hs ) hde32_disasm( code, hs )
#else
	/* Include x64 dissasembler */
	#include "hde/hde64.h"
	/* Force common name */
	typedef hde64s HDE;
	/* Force common func */
	#define HDE_DISASM( code, hs ) hde64_disasm( code, hs )
#endif
