# Source of tests/fixtures/external/pyc/tables.cpython-3*.pyc: line
# numbers that go forwards and backwards, a statement spanning lines,
# column ranges, and try/except/finally and with blocks, so the line
# tables (co_lnotab, co_linetable) and exception tables have entries of
# several kinds.
import contextlib


def parse(items):
    total = 0
    for item in items:
        try:
            value = int(
                item,
                base=10,
            )
        except ValueError as error:
            print("skipping", item, error)
            continue
        finally:
            total += 1
        if value > 100:
            break
    return total


def guarded(path):
    with contextlib.suppress(OSError):
        with open(path) as handle:
            return handle.read()
    return None


result = parse(["1", "x", "300"]) + (guarded("missing") or "").count("a")
