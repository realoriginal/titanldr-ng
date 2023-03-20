;;
;; Reflective Loader
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
[BITS 64]

;;
;; Export
;;
GLOBAL GetIp
GLOBAL Table

[SECTION .text$C]

Table:
	;;
	;; Arbitrary symbol to reference as
	;; start of hook pages
	;;
	dq	0

[SECTION .text$F]

GetIp:
	;;
	;; Execute next instruction
	;; 
	call	get_ret_ptr

get_ret_ptr:
	;;
	;; Pop address and sub diff
	;;
	pop	rax
	sub	rax, 5
	ret


Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
