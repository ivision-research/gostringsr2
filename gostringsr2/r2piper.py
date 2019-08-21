import r2pipe
import os
import time
import io
import sys
from subprocess import Popen, PIPE


class open(r2pipe.open_sync.open):
    def __init__(self, filename="", flags=[], radare2home=None):
        super(open, self).__init__("", flags)
        if filename:
            self._cmd = self._cmd_process
            if radare2home is not None:
                if not os.path.isdir(radare2home):
                    raise Exception(
                        "`radare2home` passed is invalid, leave it None or put a valid path to r2 folder"
                    )
                r2e = os.path.join(radare2home, "radare2")
            else:
                r2e = "radare2"
                if os.name == "nt":
                    # avoid errors on Windows when subprocess messes with name
                    r2e += ".exe"
            cmd = [r2e, "-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            dnull = io.open(os.devnull, "w")
            try:
                self.process = Popen(
                    cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=dnull, bufsize=0
                )
            except:
                raise Exception("ERROR: Cannot find radare2 in PATH")
            self.process.stdout.read(1)  # Reads initial \x00
            # make it non-blocking to speedup reading
            self.nonblocking = True
            if self.nonblocking:
                fd = self.process.stdout.fileno()
                if not self.__make_non_blocking(fd):
                    Exception("ERROR: Cannot make stdout pipe non-blocking")

    """ Override _cmd_process to return bytes instead of a decoded utf8 string """

    def _cmd_process(self, cmd):
        cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write((cmd + "\n").encode("utf8"))
        r = self.process.stdout
        out = b""
        sys.stdout.flush()  # flush any output before running command, in case thecommand takes a while
        c = 0
        while True:
            if self.nonblocking:
                try:
                    foo = r.read(4096)
                except:
                    continue
            else:
                foo = r.read(1)
            if foo:
                if foo.endswith(b"\0"):
                    out += foo[:-1]
                    break

                out += foo
            else:
                # if there is no any output from pipe this loop will eat CPU, probably we have to do micro-sleep here
                if self.nonblocking:
                    time.sleep(0.001)
                    c += 1
                    if c % 50 == 0:
                        print(
                            ["_", "-", "+", "-"][c // 50 % 4],
                            end="",
                            file=sys.stderr,
                            flush=True,
                        )

        if c >= 50:
            print("", file=sys.stderr, flush=True)
        return out
