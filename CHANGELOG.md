# Changelog

## 1.1.2

- Validate file is elf/pe/mach0 or throw an error
- Rearrange logic so that non-ARM/x86 architectures may work
- Add some docs to GoStringsR2
- Open r2pipe with `-2` flag to kill stderr

## 1.1.1

- Add `-s` option to generate an r2 script that can be loaded into radare2 afterwards

## 1.1.0

- Use `p8` instead of `pr` to get raw data (#1)
- Fix bug in is_a_string_ref() (#1)
- Use quietr2pipe to kill r2's stderr during run()
- Some refactoring, debug output, optimizing cross-ref boundaries for r2

## 1.0.0

- Initial release
