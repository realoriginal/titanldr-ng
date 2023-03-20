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

/* Definition */
ULONG
NTAPI
RtlRandomEx(
	_In_ PUINT32 Seed
);

typedef struct
{
	D_API( RtlRandomEx );
} API ;

/* API Hashes */
#define H_API_RTLRANDOMEX	0x7f1224f5 /* RtlRandomEx */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Returns a random string of the specified 
 * length.
 *
!*/
D_SEC( E ) VOID RandomString( _In_ PCHAR Buffer, _In_ UINT32 Length )
{
	API	Api;

	PCHAR	Alp = C_PTR( G_SYM( "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) );
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Init API */
	Api.RtlRandomEx = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );

	/* Create buffer to hold the random string */
	for ( INT Idx = 0 ; Idx < Length ; ++Idx ) {
		/* Generate random index */
		Val = NtGetTickCount();
		Val = Api.RtlRandomEx( &Val );
		Val = Api.RtlRandomEx( &Val );
		Val = Val % 26;

		/* Set character */
		Buffer[ Idx ] = Alp[ Val ];
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
