/* Deliberately tiny transfers: do not let the compiler devirtualize the probe. */
	.text
	.p2align 4
	.globl probe_call
	.globl probe_jump
	.globl probe_return
	.globl probe_elf_landing
	.globl probe_elf_plain
#if defined(__aarch64__)
	.type probe_elf_landing,%function
probe_elf_landing:
	bti jc
	mov w0, #42
	ret
	.size probe_elf_landing, .-probe_elf_landing
	.type probe_elf_plain,%function
probe_elf_plain:
	/* Deliberately invalid landing: verifies actual ELF-loader protection. */
	mov w0, #42
	ret
	.size probe_elf_plain, .-probe_elf_plain
	.type probe_call,%function
probe_call:
	bti c
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	blr x0
	ldp x29, x30, [sp], #16
	ret
	.size probe_call, .-probe_call
	.type probe_jump,%function
probe_jump:
	bti c
	mov x16, x0
	br x16
	.size probe_jump, .-probe_jump
	.type probe_return,%function
probe_return:
	bti c
	ret x0
	.size probe_return, .-probe_return
#elif defined(__x86_64__)
	.type probe_elf_landing,@function
probe_elf_landing:
	endbr64
	movl $42, %eax
	ret
	.size probe_elf_landing, .-probe_elf_landing
	.type probe_elf_plain,@function
probe_elf_plain:
	/* Deliberately invalid landing: verifies actual ELF-loader protection. */
	movl $42, %eax
	ret
	.size probe_elf_plain, .-probe_elf_plain
	.type probe_call,@function
probe_call:
	endbr64
	subq $8, %rsp
	call *%rdi
	addq $8, %rsp
	ret
	.size probe_call, .-probe_call
	.type probe_jump,@function
probe_jump:
	endbr64
	jmp *%rdi
	.size probe_jump, .-probe_jump
	.type probe_return,@function
probe_return:
	endbr64
	/* This tests IBT, not shadow stacks; reject a shadow-stack fault separately. */
	pushq %rdi
	ret
	.size probe_return, .-probe_return
#else
#error This experiment supports only AArch64 and x86-64; RV64 stays software.
#endif
	.section .note.GNU-stack,"",%progbits
