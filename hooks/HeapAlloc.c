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
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Allocates a block of heap memory, and inserts
 * into the new heap list for tracking any new
 * allocations.
 *
!*/
D_SEC( D ) PVOID WINAPI HeapAlloc_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ SIZE_T Length )
{
	API			Api;

	LPVOID			Buf = NULL;
	PTABLE			Tbl = NULL;
	PHEAP_ENTRY_BEACON	Ent = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Table header */
	Tbl = C_PTR( G_SYM( Table ) );

	/* Create a entry to hold information about the allocation */
	if ( ( Ent = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( HEAP_ENTRY_BEACON ) ) ) != NULL ) {
		/* Allocate the buffer needed */
		if ( ( Buf = Api.RtlAllocateHeap( ProcessHeap, Flags, Length ) ) != NULL ) {
			/* Setup the information */
			Ent->Buffer = C_PTR( Buf );
			Ent->Length = U_PTR( Length );

			/* Insert into the heap list */
			InsertHeadList( &Tbl->Table->HeapList, &Ent->HeapList );
		} 
		else 
		{
			/* Notify about the lack of resources */
			Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( STATUS_INSUFFICIENT_RESOURCES ) );
		};
		/* Free the entry if fail */
		if ( Buf == NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ent );
			Ent = NULL;
		};
	} 
	else 
	{
		/* Notify about the lack of resources */
		Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( STATUS_INSUFFICIENT_RESOURCES ) );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return C_PTR( Buf );
};
