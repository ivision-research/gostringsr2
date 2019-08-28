import sys
import click
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
def main(file, length, verbose, utf8):

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
        # array of [address, decoded length, string]

        for go_string in go_strings:
            s_addr, s_len, s_val = go_string
            if verbose:
                print('0x{:x} : [{}] : {}'.format(s_addr, s_len, s_val))
            else:
                print(s_val)

        g.kill()

        return 0

    except GoStringsR2Error as err:
        printe("gostringsr2 error: {}".format(err))


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
