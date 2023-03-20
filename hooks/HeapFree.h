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
 * Free's a block of memory, and removes it from
 * the list of valid allocations.
 *
!*/
D_SEC( D ) BOOL WINAPI HeapFree_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ PVOID lpMem );
