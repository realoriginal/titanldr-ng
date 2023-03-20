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
 * Searches for the requested function, else,
 * returns a hook to install if available.
 *
!*/
D_SEC( D ) PVOID WINAPI GetProcAddress_Hook( _In_ PVOID Image, _In_ PCHAR ExportName );
