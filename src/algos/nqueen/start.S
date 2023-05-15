.text
.global _start

/* Registers to hold long and pointer.  */
#define RAX_LP	rax
#define RBP_LP	rbp
#define RBX_LP	rbx
#define RCX_LP	rcx
#define RDI_LP	rdi
#define RDX_LP	rdx
#define RSI_LP	rsi
#define RSP_LP	rsp
#define R8_LP	r8
#define R9_LP	r9
#define R10_LP	r10
#define R11_LP	r11
#define R12_LP	r12
#define R13_LP	r13
#define R14_LP	r14
#define R15_LP	r15

_start:
	/* Clearing frame pointer is insufficient, use CFI.  */
	// cfi_undefined (rip)
	/* Clear the frame pointer.  The ABI suggests this be done, to mark
	   the outermost frame obviously.  */
	xorl %ebp, %ebp

	/* Extract the arguments as encoded on the stack and set up
	   the arguments for __libc_start_main (int (*main) (int, char **, char **),
		   int argc, char *argv,
		   void (*init) (void), void (*fini) (void),
		   void (*rtld_fini) (void), void *stack_end).
	   The arguments are passed via registers and on the stack:
	main:		%rdi
	argc:		%rsi
	argv:		%rdx
	init:		%rcx
	fini:		%r8
	rtld_fini:	%r9
	stack_end:	stack.	*/

	popq %rsi		/* Pop the argument count.  */
	/* argv starts just at the current stack top.  */
	mov %RSP_LP, %RDX_LP
	/* Align the stack to a 16 byte boundary to follow the ABI.  */
	and  $~15, %RSP_LP

	/* Push garbage because we push 8 more bytes.  */
	pushq %rax

	/* Provide the highest stack address to the user code (for stacks
	   which grow downwards).  */
	pushq %rsp

	/* Call the user's main function, and exit with its value.
	   But let the libc call main.  Since __libc_start_main in
	   libc.so is called very early, lazy binding isn't relevant
	   here.  Use indirect branch via GOT to avoid extra branch
	   to PLT slot.  In case of static executable, ld in binutils
	   2.26 or above can convert indirect branch into direct
	   branch.  */
	call main

	hlt			/* Crash if somehow `exit' does return.	 */