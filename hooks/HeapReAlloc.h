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
 * Rellocates a block of heap memory, and replaces
 * its original pointer with the updated buffer
 * and size.
 *
!*/
D_SEC( D ) PVOID WINAPI HeapReAlloc_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ PVOID lpMem, _In_ SIZE_T Length );
