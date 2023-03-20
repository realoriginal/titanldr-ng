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

/*!
 *
 * Purpose:
 *
 * Maps a copy of \\KnownDlls\\ntdll and calls
 * the underlying NT call to avoid detection
 * based on usermode hooks.
 *
!*/
D_SEC( D ) NTSTATUS NTAPI NtQueueApcThread_Hook( HANDLE Thread, PVOID ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3 );
