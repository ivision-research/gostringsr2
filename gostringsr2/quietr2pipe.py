import r2pipe
import os
import time
import io
import sys
from subprocess import Popen, PIPE


class open(r2pipe.open_sync.open):
    def __init__(self, filename="", flags=[], radare2home=None):
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
