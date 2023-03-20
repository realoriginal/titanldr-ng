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
 * Finds a module loaded in memory.
 *
!*/

D_SEC( E ) PVOID PebGetModule( _In_ ULONG Hash );
