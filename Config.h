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

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT32	Rc4Len;
	UINT8	KeyBuf[ 16 ];
	UINT8	Rc4Buf[ 0 ];
} CONFIG, *PCONFIG ;
