/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

typedef struct __attribute__(( packed ))
{
	TP_CALLBACK_ENVIRON PoolEnv;
} TABLE_DEBUGGER ;

/* Table allocated and stored on a test */
typedef struct __attribute__(( packed ))
{
	CLIENT_ID	ClientId;
	ULONG_PTR 	RxBuffer;
	ULONG_PTR 	RxLength;
	ULONG_PTR 	ImageLength;

	LIST_ENTRY	HeapList;
	LIST_ENTRY	PipeList;
	TABLE_DEBUGGER	Debugger;
} TABLE_HEAP, *PTABLE_HEAP ;

typedef struct __attribute__(( packed ))
{
	PTABLE_HEAP	Table;
} TABLE, *PTABLE ;
