/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#pragma once

/*!
 *
 * Purpose:
 *
 * Resolves the required imports and fills
 * in their respective entries.
 *
!*/

D_SEC( E ) VOID LdrProcessIat( _In_ PVOID Image, _In_ PVOID Directory );

/*!
 *
 * Purpose:
 *
 * Relocates the PE based on its relative base.
 *
!*/

D_SEC( E ) VOID LdrProcessRel( _In_ PVOID Image, _In_ PVOID Directory, _In_ PVOID ImageBase );

/*!
 *
 * Purpose:
 *
 * Applies a hook the import table of a PE.
 *
!*/

D_SEC( E ) VOID LdrHookImport( _In_ PVOID Image, _In_ PVOID Directory, _In_ ULONG Hash, _In_ PVOID Function );
