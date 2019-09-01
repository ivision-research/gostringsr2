# gostringsr2

gostringsr2 extracts strings from a Go binary using radare2.

Tested with radare2 3.7.0, Python 3.7, r2pipe 1.4.1, on OS X and Linux.

Tested on Go binaries with architectures: x86 (32 and 64 bit), ARM (32 and 64 bit).

Tested on Go binaries with file formats: ELF (Linux), Mach-O (OS X), PE (Windows).

## Installation

1. Install radare2.
1. Install gostringsr2 into your Python3 (virtual) environment

From Github:

```
pip install git+https://github.com/carvesystems/gostringsr2
```

or

Locally:

```
git clone https://github.com/carvesystems/gostringsr2
pip install -e gostringsr2
```

## Usage

```
Usage: gostringsr2 [OPTIONS] FILE

Options:
  -n INTEGER  minimum length, default=4
  -v          verbose
  -u          utf8 encoding instead of ascii
  -s TEXT     save output as r2 script; load in r2 with: . [script-file]
  --help      Show this message and exit.
```

## Example

Sample Go file:

```
$ cat <<SOURCE > helloworld.go
package main

func main() {
    print("hello world, how are you today?\n")
}
SOURCE

$ go build helloworld.go

$ ./helloworld
hello world, how are you today?
```

### Basic output:

Find ASCII strings of at least length 8:

```
$ gostringsr2 -n 8 helloworld|grep -B5 -A5 hello
bad write barrier buffer bounds
call from within the Go runtime
casgstatus: bad incoming values
checkmark found unmarked object
entersyscallblock inconsistent 
hello world, how are you today?
inserting span already in treap
internal error - misuse of itab
non in-use span in unswept list
pacer: sweep done at heap size 
resetspinning: not a spinning m
```

### Verbose output:

Shows debug messages and each string's virtual address and (decoded) length.

```
$ gostringsr2 -v -n 8 helloworld|grep -B5 -A5 hello
Loading file into r2: helloworld
file: helloworld
size: 1083 KB
executable: mach0
language: c
architecture: 64-bit x86
os: macos
stripped: False

Locating string table...
String table at 0x106cf20 thru 0x10713a2
Retrieving cross references...
Limited cross-ref check from 0x1001000 to 0x104ead0
Locating string references...
Retrieved 774 references to the string table
Found strings: 631
0x106f9c3 : [31] : bad write barrier buffer bounds
0x106f9e2 : [31] : call from within the Go runtime
0x106fa01 : [31] : casgstatus: bad incoming values
0x106fa20 : [31] : checkmark found unmarked object
0x106fa3f : [31] : entersyscallblock inconsistent 
0x106fa5e : [31] : hello world, how are you today?
0x106fa7d : [31] : inserting span already in treap
0x106fa9c : [31] : internal error - misuse of itab
0x106fabb : [31] : non in-use span in unswept list
0x106fada : [31] : pacer: sweep done at heap size 
0x106faf9 : [31] : resetspinning: not a spinning m
```


### r2 script output

Writes an r2 script that creates:

1. A string reference ("axs") to the string at each code locations
1. A comment ("CCu") at each code reference, `([string length]) "[first 50 characters of the string]"`
1. A flag in the strings flag space starting with `str.go.[first 20 chars of the string]`

```
$ gostringsr2 -s helloworld.r2 -v -n 8 -helloworld|grep hello
Loading file into r2: helloworld
file: helloworld
size: 1083 KB
executable: mach0
language: c
architecture: 64-bit x86
os: macos
stripped: False

Locating string table...
String table at 0x106cf40 thru 0x1071403
Retrieving cross references...
Limited cross-ref check from 0x1001000 to 0x104eaf0
Locating string references...
Retrieved 775 references to the string table
Found strings: 632
+ r2 script written to hello.r2. Load in r2 with '. [scriptfile]'
0x106fbf7 : [32] : hello world, how are you today?


$ r2 helloworld
 -- It's not you, it's me.
[0x0104a4d0]> . hello.r2
[0x0104a4d0]> axt 0x106fbf7
(nofunc); (32) "hello world, how are you today?//" 0x104ea42 [STRING] lea rax, str.go.hello_world__how_are
[0x0104a4d0]> pd 6 @0x104ea42
            0x0104ea42      488d05ae1102.  lea rax, str.go.hello_world__how_are ; (32) "hello world, how are you today?//"
            0x0104ea49      48890424       mov qword [rsp], rax
            0x0104ea4d      48c744240820.  mov qword [rsp + 8], 0x20
            0x0104ea56      e87557fdff     call sym.runtime.printstring
            0x0104ea5b      e8c04efdff     call sym.runtime.printunlock
            0x0104ea60      e83b4efdff     call sym.runtime.printlock
[0x0104a4d0]>
```
