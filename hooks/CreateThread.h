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
 * Prevents Cobalt Strike from spawning a new thread
 * if it is within its current address space, to make
 * Beacon single-threaded.
 *
!*/
D_SEC( D ) HANDLE WINAPI CreateThread_Hook( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, PTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
