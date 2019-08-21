import sys
import click
from . import GoStringsR2


def printe(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True, **kwargs)


@click.command()
@click.argument("file")
def main(file):

    g = GoStringsR2(file)

    g.load()

    printe("\nanalyzing: {}".format(g.file_info()))

    strtab = g.get_string_table()
    if strtab is None:
        printe("error: couldn't find string table")
        exit(1)

    xrefs = g.get_cross_refs()

    if xrefs is not None:
        str_refs = g.process_xrefs(xrefs, strtab["startaddr"], strtab["endaddr"])

        if len(str_refs) == 0:
            printe("error: no cross-references found to the string table")
            results = None
        else:
            results = g.find_strings(str_refs, strtab["startaddr"], strtab["data"])

        if results is not None:
            r = len(results) - 1
            while r >= 0:
                print(results[r][2].decode("ascii", errors="ignore"))
                r -= 1
    else:
        printe("error: no cross-references found; cannot locate strings.")

    g.kill()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
