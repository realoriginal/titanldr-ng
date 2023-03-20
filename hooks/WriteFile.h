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
 * Determines if the handle is a named pipe server.
 * If it is, we are required to use the overlapped
 * IO.
 *
 * Forces the overlapped IO to simulate a blocking
 * operation to mimic the original behavior while
 * being able to obfuscate for periods at a time.
 *
!*/
D_SEC( D ) BOOLEAN WINAPI WriteFile_Hook( _In_ HANDLE hFile, _In_ LPVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped );
