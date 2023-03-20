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
 * Frees the memory associated with the 
 * ReflectiveLoader before calling the
 * DllMain.
 *
!*/
D_SEC( E ) VOID PreMain( _In_ PVOID ImageBase, _In_ ULONG AddressOfEntryPoint );
