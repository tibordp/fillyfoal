# Source of the old-style FPO record in tests/fixtures/external/pdb/lld-link-x86.pdb
# (see make.sh): a function with a hand-written .debug$F FPO_DATA record, as
# MASM writes them; lld-link moves it into the PDB's "FPO data" stream.
	.text
	.globl	_filly_asm
_filly_asm:
	push	%ebp
	mov	%esp, %ebp
	mov	8(%ebp), %eax
	pop	%ebp
	ret
	.section	.debug$F,"dr"
	.rva	_filly_asm	# ulOffStart
	.long	7		# cbProcSize
	.long	0		# cdwLocals
	.short	1		# cdwParams
	.short	0x0103		# cbProlog 3, cbRegs 1, FRAME_FPO
