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
D_SEC( D ) NTSTATUS NTAPI NtMapViewOfSection_Hook( HANDLE Section, HANDLE Process, PVOID* Base, ULONG_PTR Zero, SIZE_T CommitSize, PLARGE_INTEGER Offset, PSIZE_T ViewSize, SECTION_INHERIT SectionInherit, ULONG Type, ULONG Protect );
