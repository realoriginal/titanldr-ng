;;
;; Reflective Loader
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
[BITS 64]

;;
;; Import
;;
EXTERN Titan

;;
;; Export
;;
GLOBAL Start

[SECTION .text$A]

Start:
	;;
	;; Setup stack
	;;
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	;;
	;; Execute Ldr
	;;
	sub	rsp, 020h
	call	Titan

	;;
	;; Cleanup stack
	;;
	mov	rsp, rsi
	pop	rsi

	;;
	;; Return
	;;
	ret
