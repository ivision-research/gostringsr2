#!/usr/bin/env python3

import sys
import json

from . import r2piper as r2piper


class GoStringsR2:
    def __init__(self, _file):
        self.file = _file
        self.loaded = False
        self.r2 = None

    def kill(self):
        if self.loaded:
            self.r2.quit()

    def runjson(self, cmd):
        return self.r2.cmdj(cmd)

    def run(self, cmd):
        return self.r2.cmd(cmd)

    def load(self):
        self.r2 = r2piper.open(self.file)
        self.data = {}
        self.data["symbols"] = self.runjson("isj")
        self.data["sections"] = self.runjson("iSj")
        self.data["info"] = self.runjson("ij")

        self.arch = self.data["info"]["bin"]["arch"]
        self.bintype = self.data["info"]["bin"]["bintype"]
        self.bits = self.data["info"]["bin"]["bits"]
        self.binos = self.data["info"]["bin"]["os"]

        self.loaded = True

    def file_info(self):
        if self.loaded:
            return "{}\n\t+ size={} KB\n\t+ lang={}\n\t+ arch={}-bit {}\n\t+ os={}\n\t+ type={}\n\t+ stripped={}\n\n".format(
                self.data["info"]["core"]["file"],
                self.data["info"]["core"]["size"] // 1024,
                self.data["info"]["bin"]["lang"],
                self.data["info"]["bin"]["bits"],
                self.data["info"]["bin"]["arch"],
                self.data["info"]["bin"]["os"],
                self.data["info"]["bin"]["bintype"],
                self.data["info"]["bin"]["stripped"],
            )

        return "[No file loaded]"

    def get_string_table_symbols(self, rdata):
        g_str = self.find_symbol("go.string.*")
        g_func = self.find_symbol("go.func.*")
        if g_str is not None and g_func is not None:
            g_str["tabsize"] = g_func["vaddr"] - g_str["vaddr"]
            startaddr = g_str["vaddr"] - rdata["vaddr"]
            endaddr = startaddr + g_str["tabsize"]
            g_str["table"] = rdata["data"][startaddr:endaddr]
            return g_str

        return None

    def get_rodata_section(self):
        if self.bintype == "elf":
            sname = ".rodata"
        elif self.bintype == "mach0":
            sname = ".__TEXT.__rodata"
        elif self.bintype == "pe":
            sname = ".rdata"
        return self.get_section_data(sname)

    def get_code_section(self):
        if self.bintype in ["elf", "pe"]:
            return self.get_section_info(".text")
        elif self.bintype == "mach0":
            return self.get_section_info(".__TEXT.__text")
        return None

    def get_string_table_search(self, rdata):
        if rdata is not None:
            str_start, str_size = self.find_longest_string(rdata["data"])

            if str_size > 0:
                g_str = {"vaddr": rdata["vaddr"] + str_start, "tabsize": str_size}
                startaddr = g_str["vaddr"] - rdata["vaddr"]
                endaddr = startaddr + g_str["tabsize"]
                g_str["table"] = rdata["data"][startaddr:endaddr]

                return g_str

        return None

    def find_longest_string(self, bindata):
        off = 0
        this_off = 0
        longest_off = 0
        longest_size = 0

        binlength = len(bindata)
        while off < binlength:
            b = bindata[off : off + 2]
            # Basically, terminate a "string" if 2 null bytes are seen. Seems to work for the most part.
            if b == b"\x00\x00":
                this_size = off - this_off
                if this_size > 0:
                    if this_size > longest_size:
                        longest_off = this_off
                        longest_size = this_size
                this_off = off + 2
            else:
                this_size = off - this_off
                if this_size > 0:
                    if this_size > longest_size:
                        longest_off = this_off
                        longest_size = this_size
            off += 2

        if (off - this_off) > longest_size:
            longest_off = this_off
            longest_size = off - this_off

        if longest_size > 0:
            return (longest_off, longest_size)

        return (None, 0)

    def get_string_table(self):
        rodata = self.get_rodata_section()
        stab_sym = self.get_string_table_symbols(rodata)
        stab_sym = (
            stab_sym if stab_sym is not None else self.get_string_table_search(rodata)
        )

        if stab_sym is None:
            return None
        else:
            strtab_start = stab_sym["vaddr"]
            strtab_end = strtab_start + stab_sym["tabsize"]
            strtab = {
                "startaddr": strtab_start,
                "endaddr": strtab_end,
                "data": stab_sym["table"],
            }
            return strtab

    def find_symbol(self, symbol_name):
        for sym in self.data["symbols"]:
            if sym["name"] == symbol_name:
                return sym
        return None

    def get_cross_refs_x86(self):
        self.run("/ra")
        return self.run("axq")

    def get_cross_refs_arm(self):
        self.run("aae")
        return self.run("axq")

    def get_cross_refs(self):
        xrefs = None
        if self.arch == "x86":
            xrefs = self.get_cross_refs_x86()
        elif self.arch == "arm":
            xrefs = self.get_cross_refs_arm()
        return xrefs

    def get_section_info(self, section_name):
        for secobj in self.data["sections"]:
            if secobj["name"].endswith(section_name):
                return secobj
        return None

    def get_section_data(self, section_name):
        secobj = self.get_section_info(section_name)
        if secobj is not None:
            s_base = secobj["vaddr"]
            s_size = secobj["vsize"]
            rdsize = 2048
            i = 0
            sdata = b""
            while s_size > 0:
                c = "pr {} @0x{:x}".format(min(rdsize, s_size), s_base + i * 2048)
                sdat = self.run(c)
                sdata += sdat
                i += 1
                s_size -= rdsize

            return {"name": section_name, "vaddr": s_base, "data": sdata}
        return None

    def find_strings(self, refs, tablebase, tabledata):
        # refs.keys() = address, refs.values() = count
        refs_addrs = sorted(refs.keys(), reverse=True)

        all_strings = []
        for r in refs_addrs:
            # r = virtual addr of a string
            # subtract vaddr of section to get offset into
            r_offset = r - tablebase
            if len(all_strings) > 0:
                last_ref = all_strings[len(all_strings) - 1][0] - tablebase
                r_end_offset = last_ref
            else:
                r_end_offset = len(tabledata)

            r_str = tabledata[r_offset:r_end_offset]
            all_strings.append([tablebase + r_offset, r_end_offset - r_offset, r_str])

        return all_strings

    def is_a_string_ref(
        self, src_addr, dst_addr, strtab_addr, strtab_endaddr, code_section
    ):
        if dst_addr >= strtab_addr and dst_addr < strtab_endaddr:
            if code_section is None:
                return True
            else:
                return dst_addr >= code_section["vaddr"] and src_addr < (
                    code_section["vaddr"] + code_section["size"]
                )

        return False

    def process_xrefs(self, xrefs, strtab_start, strtab_end):
        str_refs = {}

        code_section = self.get_code_section()

        # 0x01640839 -> 0x016408a9  CALL
        for line in xrefs.split(b"\n"):
            lparts = line.split(b" ")
            # 0 = src, 1= arrow, 2 = dst, 3=empty, 4=type
            if len(lparts) == 5:
                r_src = int(lparts[0].decode("ascii"), 16)
                r_dst = int(lparts[2].decode("ascii"), 16)
                if self.is_a_string_ref(
                    r_src, r_dst, strtab_start, strtab_end, code_section
                ):
                    str_refs[r_dst] = (
                        0 if r_dst not in str_refs.keys() else str_refs[r_dst]
                    ) + 1

        return str_refs
