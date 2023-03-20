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
 * Encrypts every heap allocation made by Beacon
 * using ARC-4 symetric algorithm.
 *
!*/
D_SEC( E ) VOID HeapEncryptDecrypt( _In_ PCHAR Key, _In_ UINT32 KeyLength );
