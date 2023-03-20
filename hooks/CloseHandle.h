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
 * Removes a pipe handle from the list.
 *
!*/
D_SEC( D ) BOOL WINAPI CloseHandle_Hook( _In_ HANDLE hObject );
