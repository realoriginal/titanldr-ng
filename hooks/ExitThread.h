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
 * Frees the memory associated with beacon, and 
 * frees itself from memory.
 *
!*/

D_SEC( D ) VOID WINAPI ExitThread_Hook( _In_ DWORD ExitCode );
