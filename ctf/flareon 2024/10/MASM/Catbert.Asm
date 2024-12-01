    OPTION DOTNAME                          ; required for macro files
    option casemap:none                     ; case sensitive

    include Catbert.inc
    
.code

VMHandler:   

arg_0           = qword ptr  8
arg_8           = qword ptr  10h
arg_10          = qword ptr  18h

                mov     [rsp+arg_0], rbx
                mov     [rsp+arg_8], rsi
                mov     [rsp+arg_10], rdi
                push    r14
                sub     rsp, 20h
                mov     rdi, opcodes
                lea     r9, byte_E86C8
                and     qword_168ED0, 0
                lea     r14, qword_E86C0
                mov     qword_E86C0, rdi
                mov     esi, 8

loc_312B2:                              ; CODE XREF: VMHandler+B9?j
                                        ; VMHandler+1CE?j
                mov     qword_E8EC8, r9

loc_312B9:                              ; CODE XREF: VMHandler+291?j
                                        ; VMHandler+2C8?j ...
                mov     rdx, qword_E86C0
                movzx   eax, byte ptr [rdx]
                inc     qword_E86C0
                mov     ecx, eax
                cmp     eax, 13h
                ja      loc_3160B
                jz      loc_315F0
                cmp     eax, 9
                ja      loc_31456
                jz      loc_31447
                test    al, al
                jz      loc_31907
                sub     ecx, 1
                jz      loc_31414
                sub     ecx, 1
                jz      loc_313E6
                sub     ecx, 1
                jz      loc_313B4
                sub     ecx, 1
                jz      short loc_31379
                sub     ecx, 1
                jz      short loc_3135F
                sub     ecx, 1
                jz      short loc_31338
                sub     ecx, 1
                jz      short loc_3132F
                cmp     ecx, 1
                jnz     loc_31919
                sub     r9, rsi
                jmp     short loc_312B2
; ---------------------------------------------------------------------------

loc_3132F:                              ; CODE XREF: VMHandler+AB?j
                mov     rax, [r9-8]
                jmp     loc_3140F
; ---------------------------------------------------------------------------

loc_31338:                              ; CODE XREF: VMHandler+A6?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rcx, [r9]
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                mov     [r14+rax*8+810h], rcx
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_3135F:                              ; CODE XREF: VMHandler+A1?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                mov     rax, [r14+rax*8+810h]
                jmp     loc_3140F
; ---------------------------------------------------------------------------

loc_31379:                              ; CODE XREF: VMHandler+9C?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   eax, byte ptr [rdx-1]
                movzx   ecx, byte ptr [rdx-2]
                shl     rcx, 8
                add     rcx, rax
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                mov     [r14+rcx*8+810h], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_313B4:                              ; CODE XREF: VMHandler+93?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   eax, byte ptr [rdx-1]
                movzx   ecx, byte ptr [rdx-2]
                shl     rcx, 8
                add     rcx, rax
                mov     rax, [r14+rcx*8+810h]

loc_313DD:                              ; CODE XREF: VMHandler+1E0?j
                add     [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_313E6:                              ; CODE XREF: VMHandler+8A?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   eax, byte ptr [rdx-1]
                movzx   ecx, byte ptr [rdx-2]
                shl     rcx, 8
                add     rcx, rax
                mov     rax, [r14+rcx*8+810h]

loc_3140F:                              ; CODE XREF: VMHandler+BF?j
                                        ; VMHandler+100?j
                mov     [r9], rax
                jmp     short loc_31438
; ---------------------------------------------------------------------------

loc_31414:                              ; CODE XREF: VMHandler+81?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   ecx, byte ptr [rdx-2]
                movzx   eax, byte ptr [rdx-1]
                shl     rcx, 8
                add     rcx, rax
                mov     [r9], rcx

loc_31438:                              ; CODE XREF: VMHandler+19E?j
                mov     r9, qword_E8EC8
                add     r9, rsi
                jmp     loc_312B2
; ---------------------------------------------------------------------------

loc_31447:                              ; CODE XREF: VMHandler+70?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                jmp     short loc_313DD
; ---------------------------------------------------------------------------

loc_31456:                              ; CODE XREF: VMHandler+6A?j
                sub     ecx, 0Ah
                jz      loc_315C6
                sub     ecx, 1
                jz      loc_315B0
                sub     ecx, 1
                jz      loc_3158A
                sub     ecx, 1
                jz      loc_31576
                sub     ecx, 1
                jz      loc_31552
                sub     ecx, 1
                jz      loc_3150D
                sub     ecx, 1
                jz      short loc_314D6
                sub     ecx, 1
                jz      short loc_314B7
                cmp     ecx, 1
                jnz     loc_31919
                sub     r9, rsi
                xor     ecx, ecx
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                cmp     [r9-8], rax
                setb    cl
                jmp     short loc_314CD
; ---------------------------------------------------------------------------

loc_314B7:                              ; CODE XREF: VMHandler+220?j
                sub     r9, rsi
                xor     ecx, ecx
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                cmp     [r9-8], rax
                setz    cl

loc_314CD:                              ; CODE XREF: VMHandler+241?j
                                        ; VMHandler+392?j ...
                mov     [r9-8], rcx
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_314D6:                              ; CODE XREF: VMHandler+21B?j
                mov     rdx, qword_E86C0
                sub     r9, rsi
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   ecx, byte ptr [rdx-2]
                movzx   eax, byte ptr [rdx-1]
                shl     rcx, 8
                add     rcx, rax
                mov     qword_E8EC8, r9
                cmp     qword ptr [r9], 0
                jnz     loc_312B9
                jmp     short loc_31542
; ---------------------------------------------------------------------------

loc_3150D:                              ; CODE XREF: VMHandler+212?j
                mov     rdx, qword_E86C0
                sub     r9, rsi
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   ecx, byte ptr [rdx-2]
                movzx   eax, byte ptr [rdx-1]
                shl     rcx, 8
                add     rcx, rax
                mov     qword_E8EC8, r9
                cmp     qword ptr [r9], 0
                jz      loc_312B9

loc_31542:                              ; CODE XREF: VMHandler+297?j
                lea     rax, [rcx+rdi]
                mov     qword_E86C0, rax
                jmp     loc_312B9
; ---------------------------------------------------------------------------

loc_31552:                              ; CODE XREF: VMHandler+209?j
                mov     rdx, qword_E86C0
                movzx   eax, byte ptr [rdx]
                movzx   ecx, byte ptr [rdx+1]
                shl     rax, 8
                add     rax, rdi
                add     rcx, rax
                mov     qword_E86C0, rcx
                jmp     loc_312B9
; ---------------------------------------------------------------------------

loc_31576:                              ; CODE XREF: VMHandler+200?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9-8]
                imul    rax, [r9]
                jmp     short loc_315A7
; ---------------------------------------------------------------------------

loc_3158A:                              ; CODE XREF: VMHandler+1F7?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                cmp     qword ptr [r9], 0
                jz      loc_3190E
                mov     rax, [r9-8]
                xor     edx, edx
                div     qword ptr [r9]

loc_315A7:                              ; CODE XREF: VMHandler+314?j
                                        ; VMHandler+46C?j ...
                mov     [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_315B0:                              ; CODE XREF: VMHandler+1EE?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                sub     [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_315C6:                              ; CODE XREF: VMHandler+1E5?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   ecx, byte ptr [rdx-2]
                movzx   eax, byte ptr [rdx-1]
                shl     rcx, 8
                add     rcx, rax
                add     [r9-8], rcx
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_315F0:                              ; CODE XREF: VMHandler+61?j
                sub     r9, rsi
                xor     ecx, ecx
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                cmp     [r9-8], rax
                setbe   cl
                jmp     loc_314CD
; ---------------------------------------------------------------------------

loc_3160B:                              ; CODE XREF: VMHandler+5B?j
                cmp     ecx, 1Dh
                ja      loc_31737
                jz      loc_3171B
                sub     ecx, 14h
                jz      loc_31700
                sub     ecx, 1
                jz      loc_316E5
                sub     ecx, 1
                jz      loc_316B6
                sub     ecx, 1
                jz      short loc_3169D
                sub     ecx, 1
                jz      loc_31915
                sub     ecx, 1
                jz      short loc_3169D
                sub     ecx, 1
                jz      short loc_31687
                sub     ecx, 1
                jz      short loc_31671
                cmp     ecx, 1
                jnz     loc_31919
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                and     [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_31671:                              ; CODE XREF: VMHandler+3DC?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                or      [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_31687:                              ; CODE XREF: VMHandler+3D7?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                xor     [r9-8], rax
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_3169D:                              ; CODE XREF: VMHandler+3C4?j
                                        ; VMHandler+3D2?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                mov     qword_168ED0, rax
                jmp     loc_312B9
; ---------------------------------------------------------------------------

loc_316B6:                              ; CODE XREF: VMHandler+3BB?j
                mov     rdx, qword_E86C0
                add     rdx, 2
                mov     qword_E86C0, rdx
                movzx   eax, byte ptr [rdx-1]
                movzx   ecx, byte ptr [rdx-2]
                shl     rcx, 8
                add     rcx, rax
                xor     eax, eax
                cmp     [r9-8], rcx
                setnb   al
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_316E5:                              ; CODE XREF: VMHandler+3B2?j
                sub     r9, rsi
                xor     ecx, ecx
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                cmp     [r9-8], rax
                setnb   cl
                jmp     loc_314CD
; ---------------------------------------------------------------------------

loc_31700:                              ; CODE XREF: VMHandler+3A9?j
                sub     r9, rsi
                xor     ecx, ecx
                mov     qword_E8EC8, r9
                mov     rax, [r9]
                cmp     [r9-8], rax
                setnbe  cl
                jmp     loc_314CD
; ---------------------------------------------------------------------------

loc_3171B:                              ; CODE XREF: VMHandler+3A0?j
                sub     r9, rsi
                xor     edx, edx
                mov     qword_E8EC8, r9
                mov     rax, [r9-8]
                div     qword ptr [r9]
                mov     [r9-8], rdx
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_31737:                              ; CODE XREF: VMHandler+39A?j
                sub     ecx, 1Eh
                jz      loc_318EA
                sub     ecx, 1
                jz      loc_318D7
                sub     ecx, 1
                jz      loc_318AB
                sub     ecx, 1
                jz      loc_31884
                sub     ecx, 1
                jz      loc_31857
                sub     ecx, 1
                jz      loc_3182A
                sub     ecx, 1
                jz      loc_31800
                sub     ecx, 1
                jz      short loc_317D6
                cmp     ecx, 1
                jnz     loc_31919
                ;mov     rax, FILE_HANDLE_PTR ;.GetFileInfo
                lea     edx, [rcx+4Eh]
                sub     r9, rsi
                mov     qword_E8EC8, r9
                ;mov     r8, [rax+40h]
                mov     rbx, [r9]
                mov     rcx, r8
                ;call    qword ptr [r8+28h]
                or      edx, 0FFFFFFFFh
                lea     r8, aC          ; "%c"
                or      ecx, edx
                mov     r9, rbx
                
                
                ;call    ShowMessage
;                mov     rax, FILE_HANDLE_PTR.GetFileInfo
;                mov     edx, 47h ; 'G'
;                mov     r8, [rax+40h]
;                mov     rcx, r8
;                call    qword ptr [r8+28h]
                jmp     loc_318FB
; ---------------------------------------------------------------------------

loc_317D6:                              ; CODE XREF: VMHandler+505?j
                sub     r9, rsi
                mov     ecx, esi
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     rdx, [r9-8]
                mov     rax, rdx
                shl     rax, cl
                mov     rcx, [r9]
                sar     rdx, cl
                or      rax, rdx
                movzx   eax, al
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_31800:                              ; CODE XREF: VMHandler+4FC?j
                sub     r9, rsi
                mov     ecx, esi
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     r8, [r9-8]
                mov     rdx, r8
                sar     rdx, cl
                mov     rcx, [r9]
                shl     r8, cl
                or      rdx, r8
                movzx   eax, dl
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_3182A:                              ; CODE XREF: VMHandler+4F3?j
                sub     r9, rsi
                mov     ecx, 10h
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     rdx, [r9-8]
                mov     rax, rdx
                shl     rax, cl
                mov     rcx, [r9]
                sar     rdx, cl
                or      rax, rdx
                movzx   eax, ax
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_31857:                              ; CODE XREF: VMHandler+4EA?j
                sub     r9, rsi
                mov     ecx, 10h
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     r8, [r9-8]
                mov     rdx, r8
                sar     rdx, cl
                mov     rcx, [r9]
                shl     r8, cl
                or      rdx, r8
                movzx   eax, dx
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_31884:                              ; CODE XREF: VMHandler+4E1?j
                sub     r9, rsi
                mov     ecx, 20h ; ' '
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     rdx, [r9-8]
                mov     rax, rdx
                shl     rax, cl
                mov     rcx, [r9]
                shr     rdx, cl
                or      rax, rdx
                jmp     short loc_318D0
; ---------------------------------------------------------------------------

loc_318AB:                              ; CODE XREF: VMHandler+4D8?j
                sub     r9, rsi
                mov     ecx, 20h ; ' '
                mov     qword_E8EC8, r9
                sub     cl, [r9]
                mov     r8, [r9-8]
                mov     rax, r8
                shr     rax, cl
                mov     rcx, [r9]
                shl     r8, cl
                or      rax, r8

loc_318D0:                              ; CODE XREF: VMHandler+635?j
                mov     eax, eax
                jmp     loc_315A7
; ---------------------------------------------------------------------------

loc_318D7:                              ; CODE XREF: VMHandler+4CF?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rcx, [r9]
                shr     qword ptr [r9-8], cl
                jmp     short loc_318FB
; ---------------------------------------------------------------------------

loc_318EA:                              ; CODE XREF: VMHandler+4C6?j
                sub     r9, rsi
                mov     qword_E8EC8, r9
                mov     rcx, [r9]
                shl     qword ptr [r9-8], cl

loc_318FB:                              ; CODE XREF: VMHandler+E6?j
                                        ; VMHandler+13B?j ...
                mov     r9, qword_E8EC8
                jmp     loc_312B9
; ---------------------------------------------------------------------------

loc_31907:                              ; CODE XREF: VMHandler+78?j
                mov     eax, 4
                jmp     short loc_3191E
; ---------------------------------------------------------------------------

loc_3190E:                              ; CODE XREF: VMHandler+324?j
                mov     eax, 1
                jmp     short loc_3191E
; ---------------------------------------------------------------------------

loc_31915:                              ; CODE XREF: VMHandler+3C9?j
                xor     eax, eax
                jmp     short loc_3191E
; ---------------------------------------------------------------------------

loc_31919:                              ; CODE XREF: VMHandler+B0?j
                                        ; VMHandler+225?j ...
                mov     eax, 3

loc_3191E:                              ; CODE XREF: VMHandler+698?j
                                        ; VMHandler+69F?j ...
                mov     rbx, [rsp+28h+arg_0]
                mov     rsi, [rsp+28h+arg_8]
                mov     rdi, [rsp+28h+arg_10]
                add     rsp, 20h
                pop     r14
                ret

WinMainCRTStartup proc 
    
    
     mov eax, meme_id
     imul rax, 8
     
     mov rcx,offset memes
     add rcx,rax
     mov rcx, qword ptr[rcx]
     mov edx, dword ptr[rcx+8]
     add rcx,rdx
    
 
     mov opcodes,rcx
     mov r8, szKey

     
    mov     al, [r8]
    mov     [rcx+5], al
    mov     al, [r8+2]
    mov     [rcx+4], al
    mov     al, [r8+4]
    mov     [rcx+0Ch], al
    mov     al, [r8+6]
    mov     [rcx+0Bh], al
    mov     al, [r8+8]
    mov     [rcx+13h], al
    mov     al, [r8+0Ah]
    mov     [rcx+12h], al
    mov     al, [r8+0Ch]
    mov     [rcx+1Ah], al
    mov     al, [r8+0Eh]
    mov     [rcx+19h], al
    mov     al, [r8+10h]
    mov     [rcx+21h], al
    mov     al, [r8+12h]
    mov     [rcx+20h], al
    mov     al, [r8+14h]
    mov     [rcx+28h], al
    mov     al, [r8+16h]
    mov     [rcx+27h], al
    mov     al, [r8+18h]
    mov     [rcx+2Fh], al
    mov     al, [r8+1Ah]
    mov     [rcx+2Eh], al
    mov     al, [r8+1Ch]
    mov     [rcx+36h], al
    mov     al, [r8+1Eh]
    mov     [rcx+35h], al
    call VMHandler
    mov rax, qword_168ED0
    test rax,rax
    jnz @success    
    jmp @exit
    
    
 @success:
    
    invoke  GetModuleHandle, NULL
    mov hInstance, rax
    invoke  GetCommandLine
    mov     CommandLine, rax
    
    invoke  InitCommonControls
    mov     icc.dwSize, sizeof INITCOMMONCONTROLSEX
    mov     icc.dwICC, ICC_COOL_CLASSES or ICC_STANDARD_CLASSES or ICC_WIN95_CLASSES
    invoke  InitCommonControlsEx, addr icc
    
    invoke  WinMain, hInstance, NULL, CommandLine, SW_SHOWDEFAULT
@exit:
    invoke  ExitProcess, eax
    
    ret

WinMainCRTStartup endp

ShowMessage proc
    
    
    ret

ShowMessage endp
WinMain proc hInst:HINSTANCE, hPrevInstance:HINSTANCE, lpCmdLine:LPSTR, nCmdShow:DWORD

    invoke DialogBoxParam, hInst, IDD_DIALOG, NULL, addr DlgProc, NULL
    invoke ExitProcess, rax

WinMain endp

DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM

    .if uMsg==WM_INITDIALOG
        ; code that runs before dialog shows up
        ; ret TRUE
    .elseif uMsg==WM_COMMAND
        ; code of controls, buttons, checkboxes...
    .elseif uMsg==WM_CLOSE
        invoke EndDialog, hWnd, 0
        ret
    .else
        mov eax, FALSE
        ret
    .endif
    mov eax, TRUE
    ret

DlgProc endp

end

