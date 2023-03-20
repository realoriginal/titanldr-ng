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
 * Allocates a block of heap memory, and inserts
 * into the new heap list for tracking any new
 * allocations.
 *
!*/
D_SEC( D ) PVOID WINAPI HeapAlloc_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ SIZE_T Length );
