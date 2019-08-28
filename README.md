# gostrings-r2

gostrings-r2 extracts strings from a Go binary using radare2.

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
gostringsr2 [OPTIONS] FILE

Options:
  -n INTEGER  minimum length, default=4
  -v          verbose
  -u          utf8 encoding instead of ascii
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
