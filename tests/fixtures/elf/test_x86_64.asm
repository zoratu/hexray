; Test x86_64 assembly with control flow
; nasm -f elf64 test_x86_64.asm -o test_x86_64.o
; ld -o test_x86_64 test_x86_64.o

BITS 64
global _start

section .text

; Simple function with if/else
; int check_value(int x) {
;     if (x > 10) return 1;
;     else return 0;
; }
check_value:
    push rbp
    mov rbp, rsp
    cmp edi, 10
    jle .else
    mov eax, 1
    jmp .end
.else:
    mov eax, 0
.end:
    pop rbp
    ret

; Function with loop
; int sum_to_n(int n) {
;     int sum = 0;
;     for (int i = 0; i < n; i++) {
;         sum += i;
;     }
;     return sum;
; }
sum_to_n:
    push rbp
    mov rbp, rsp
    xor eax, eax        ; sum = 0
    xor ecx, ecx        ; i = 0
.loop:
    cmp ecx, edi
    jge .done
    add eax, ecx
    inc ecx
    jmp .loop
.done:
    pop rbp
    ret

_start:
    ; Call check_value(15)
    mov edi, 15
    call check_value

    ; Call sum_to_n(10)
    mov edi, 10
    call sum_to_n

    ; Exit with result
    mov edi, eax
    mov eax, 60         ; syscall: exit
    syscall
