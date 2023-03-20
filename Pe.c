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

/*!
 *
 * Purpose:
 *
 * Searches for a export matching the specified hash.
 *
!*/

D_SEC( E ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ ULONG Hash ) 
{
	ULONG			Idx = 0;
	PUINT16			Aoo = NULL;
	PUINT32			Aof = NULL;
	PUINT32			Aon = NULL;
	PIMAGE_DOS_HEADER	Hdr = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	Hdr = C_PTR( Image );
	Nth = C_PTR( U_PTR( Hdr ) + Hdr->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Has a EAT? */
	if ( Dir->VirtualAddress ) {
		Exp = C_PTR( U_PTR( Hdr ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Hdr ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Hdr ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Hdr ) + Exp->AddressOfNameOrdinals );

		/* Enumerate exports */
		for ( Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Create a hash of the string and compare */
			if ( HashString( C_PTR( U_PTR( Hdr ) + Aon[ Idx ] ), 0 ) == Hash ) {
				return C_PTR( U_PTR( Hdr ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	return NULL;
};
