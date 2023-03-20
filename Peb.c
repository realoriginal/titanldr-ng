/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Finds a module loaded in memory.
 *
!*/

D_SEC( E ) PVOID PebGetModule( _In_ ULONG Hash )
{
	PPEB			Peb = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get pointer to list */
	Peb = NtCurrentPeb();
	Hdr = & Peb->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
		Ldr = C_PTR( Ent );

		/* Compare the DLL Name! */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == Hash ) {
			return Ldr->DllBase;
		};
	};
	return NULL;
};
