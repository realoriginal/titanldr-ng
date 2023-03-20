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
 * If a pipe is not using non-overlapped IO,
 * the pipe will be saved into a list, and
 * forced to be async-IO.
 *
 * The other pipe hooks will attempt to then
 * obfuscate on the handle when performing
 * Read, write, and connect operations.
 *
!*/
D_SEC( D ) HANDLE WINAPI CreateNamedPipeA_Hook( _In_ LPCSTR lpName, _In_ DWORD dwOpenMode, _In_ DWORD dwPipeMode, _In_ DWORD nMaxInstances, _In_ DWORD nOutBufferSize, _In_ DWORD nInBufferSize, _In_ DWORD nDefaultTimeout, _In_ LPSECURITY_ATTRIBUTES lpAttributes );
