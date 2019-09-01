import sys
import click
import re
from os import path
from . import GoStringsR2, GoStringsR2Error


def printe(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True, **kwargs)


@click.command()
@click.argument("file")
@click.option(
    "-n", "length", is_flag=False, default=4, help="minimum length, default=4"
)
@click.option("-v", "verbose", is_flag=True, help="verbose")
@click.option("-u", "utf8", is_flag=True, help="utf8 encoding instead of ascii")
@click.option(
    "-s", "r2script", help="save output as r2 script; load in r2 with: . [script-file]"
)
def main(file, length, verbose, utf8, r2script):

    if not path.isfile(file):
        printe("invalid file {}".format(file))
        return 1

    g = GoStringsR2(file, verbose)

    try:
        g.load()

        encoding = "ascii"
        if utf8:
            encoding = "utf8"

        go_strings = g.get_strings(length, encoding)
        # array of [address, decoded length, string, byte length, list of code refs]

        if r2script is not None:
            r2scriptfile = open(r2script, "w")
            r2scriptfile.writelines(
                [
                    "fs strings\n",
                    "e asm.comments = false\n",  # The big Go string gets in the way
                    "e asm.usercomments = true\n",
                ]
            )
        else:
            r2scriptfile = None

        for go_string in go_strings:
            s_addr, s_len, s_val, s_binlen, s_refs = go_string

            # get rid of "binary" chars before printing, otherwise pipes to grep are unhappy
            s_val = re.sub("[\x00\x08]", "", s_val)

            if verbose:
                print("0x{:x} : [{}] : {}".format(s_addr, s_len, s_val))
            else:
                print(s_val)

            if r2scriptfile is not None:
                r2scriptfile.writelines(g.get_r2_script_for_string(go_string, encoding))

        if r2scriptfile is not None:
            printe(
                "+ r2 script written to {}. Load in r2 with '. [scriptfile]'".format(
                    r2script
                )
            )
            r2scriptfile.close()

        g.kill()

        return 0

    except GoStringsR2Error as err:
        printe("gostringsr2 error: {}".format(err))


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
