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
 * Redirects DnsQuery_A over a DNS/HTTP(s)
 * provider.
 *
!*/

D_SEC( D ) DNS_STATUS WINAPI DnsQuery_A_Hook( _In_ PCSTR pszName, _In_ WORD wType, _In_ DWORD Options, _In_ PVOID pExtra, _Out_ PDNS_RECORD * ppQueryResults, _In_ PVOID pReserved );
