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
D_SEC( D ) BOOL WINAPI ReadProcessMemory_Hook( _In_ HANDLE hProcess, LPVOID Address, LPVOID Buffer, SIZE_T Length, SIZE_T *Written );
