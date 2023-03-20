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
 * Executes NtWaitForSingleObject while obfuscated.
 * Once the wait has completed, the result will be
 * returned back to us.
 *
!*/
D_SEC( E ) NTSTATUS NTAPI ObfNtWaitForSingleObject( _In_ HANDLE Handle, _In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Timeout );
