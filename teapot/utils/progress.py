import sys


def print_progress_bar(status: str, idx: int, count: int):
    if not sys.stdout.isatty():
        step = max(1, count // 10)
        if idx == 1 or idx == count or idx % step == 0:
            print(f"[teapot] {status}: {idx} / {count}", flush=True)
        return

    bar_length = 50
    progress = idx / count
    block = int(round(bar_length * progress))
    text = "\r{0}: [{1}] {2}% ({3} / {4})".format(
        status, "#" * block + "-" * (bar_length - block), int(progress * 100), idx, count)
    sys.stdout.write(text)
    sys.stdout.flush()
