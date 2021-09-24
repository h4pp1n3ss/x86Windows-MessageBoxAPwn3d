# Windows/x86 - Dynamic MessageBoxA PEB & Import Address Tab
 
## Description: 

This is a shellcode which
pop a MessageBox and show the text "Pwn3d by h4pp1n3ss". In order to accomplish this task the shellcode uses
the PEB method to locate the baseAddress of the required module and the Export Directory Table
to locate symbols. Also the shellcode uses a hash function to gather dynamically the required 
symbols without worry about the length. 


- Author: h4pp1n3ss
- Date: Wed 09/23/2021
- Tested on: Microsoft Windows [Version 10.0.19042.1237]

# Windows API 

This shellcode uses two Windows API

### WinExec

[MessageBoxA Function Prototype](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)
```c
int MessageBoxA(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);
```

and 

### TerminateProcess

[TerminateProcess Function Prototype](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)

```c
 BOOL TerminateProcess(
  HANDLE hProcess,	 -> 0xffffffff
  UINT   uExitCode	 -> EAX
 );
```


# Resources

- [Corelan - Exploit writing tutorial part 9](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)
- [Shell-storm](http://shell-storm.org/shellcode/)
- [Phrack - History and Advances in Windows Shellcode](http://www.phrack.org/issues/62/7.html#article)
- [Skape - Understanding Windows Shellcode ](http://www.hick.org/code/skape/papers/win32-shellcode.pdf)
