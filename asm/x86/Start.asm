;;
;; Reflective Loader
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
[BITS 32]

;;
;; Import
;;
EXTERN _Titan

;;
;; Export
;;
GLOBAL _Start

[SECTION .text$A]

_Start:
	;;
	;; Setup stack
	;;
	push	ebp
	mov	ebp, esp

	;;
	;; Execute Ldr
	;;
	call	_Titan

	;;
	;; Cleanup stack
	;;
	mov	esp, ebp
	pop	ebp

	;;
	;; Return
	;;
	ret
