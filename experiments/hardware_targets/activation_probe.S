    .section .teapot_bti_normal,"ax",%progbits
    .p2align 2
    .global __teapot_bti_text_start, __teapot_bti_text_end
__teapot_bti_text_start:
    .word 0xd50324df
#ifdef BAD_SECOND_WORD
    nop
#else
    .word 0xd280a29f
#endif
    mov w0, #42
    ret
#ifdef BAD_LANDING
    .word BAD_LANDING
    nop
#endif
__teapot_bti_text_end:
    .section .teapot_transient,"ax",%progbits
    .p2align 2
    .global __teapot_bti_transient_start, __teapot_bti_transient_end
#ifdef OVERLAP_SHADOW
    .set __teapot_bti_transient_start, __teapot_bti_text_start
    .set __teapot_bti_transient_end, __teapot_bti_text_end
#else
__teapot_bti_transient_start:
    nop
    ret
__teapot_bti_transient_end:
#endif
    .section .note.GNU-stack,"",%progbits
