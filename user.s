fibonacci:
        pushq   %rbp
        movq    %rsp, %rbp
        pushq   %rbx
        subq    $24, %rsp
        movl    %edi, -20(%rbp)
        cmpl    $0, -20(%rbp)
        jg      .L2
        movl    $0, %eax
        jmp     .L3
.L2:
        cmpl    $1, -20(%rbp)
        jne     .L4
        movl    $1, %eax
        jmp     .L3
.L4:
        movl    -20(%rbp), %eax
        subl    $1, %eax
        movl    %eax, %edi
        call    fibonacci
        movq    %rax, %rbx
        movl    -20(%rbp), %eax
        subl    $2, %eax
        movl    %eax, %edi
        call    fibonacci
        addq    %rbx, %rax
.L3:
        movq    -8(%rbp), %rbx
        leave
        ret
.LC0:
        .string "Fibonacci(%d) = %lld\n"
main:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movl    $5, -4(%rbp)
        movl    -4(%rbp), %eax
        movl    %eax, %edi
        call    fibonacci
        movq    %rax, %rdx
        movl    -4(%rbp), %eax
        movl    %eax, %esi
        movl    $.LC0, %edi
        movl    $0, %eax
        call    printf
        movl    $0, %eax
        leave
        ret
