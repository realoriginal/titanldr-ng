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

typedef struct
{
	LIST_ENTRY	HeapList;
	LPVOID		Buffer;
	SIZE_T		Length;
} HEAP_ENTRY_BEACON, *PHEAP_ENTRY_BEACON ;
