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
 * Creates a hash summary of the input buffer.
 * If a length is not provided, it assumes it
 * is NULL terminated.
 *
!*/

D_SEC( E ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ ULONG Length );
