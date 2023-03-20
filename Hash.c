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
 * Creates a hash summary of the input buffer.
 * If a length is not provided, it assumes it
 * is NULL terminated.
 *
!*/

D_SEC( E ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ ULONG Length ) 
{
	UCHAR	Cur = 0;
	ULONG	Djb = 0;
	PUCHAR	Ptr = NULL;

	Djb = 5381;
	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		/* Get the current character */
		Cur = * Ptr;

		if ( ! Length ) {
			/* NULL terminated? */
			if ( ! * Ptr ) {
				break;
			};
		} else {
			/* Position exceed the length of the buffer? */
			if ( ( ULONG )( Ptr - ( PUCHAR ) Buffer ) >= Length ) {
				break;
			};
			/* NULL terminated? */
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};
		/* Lowercase */
		if ( Cur >= 'a' ) {
			Cur -= 0x20;
		};

		/* Hash the character */
		Djb = ( ( Djb << 5 ) + Djb ) + Cur; ++Ptr;
	};
	return Djb;
};
