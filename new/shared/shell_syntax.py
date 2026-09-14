"""Shell line syntax: pipelines and redirections.

Pure text handling for one `;`-separated segment. It recognises the shapes
attackers actually type and hands them back to the caller — it knows nothing
about commands, so the engine still runs every stage itself and a pipeline's
filtered output comes from the simulated filesystem rather than being invented.

Redirections are honoured rather than echoed: `cmd > /dev/null` produces no
visible output, `cmd > /tmp/x` writes into the fake filesystem, and
`bogus 2>/dev/null` swallows the error the way bash would. Nothing here can
touch the real filesystem or network; the only writable thing is the fake tree.
"""

import re
from dataclasses import dataclass

DEVNULL = "/dev/null"

# Longest first, so `2>&1` is not read as `2>` followed by `&1`.
_OPERATORS = ("2>&1", "&>>", "2>>", "1>>", "2>", "1>", "&>", ">>", ">")

# Filters a pipeline may hand text to. Anything else is refused, not guessed.
FILTERS = ("cat", "grep", "head", "tail", "cut", "sort", "uniq", "wc")


@dataclass
class Redirect:
    """Where a segment's output was sent."""

    stdout_target: str | None = None
    stderr_target: str | None = None
    stdin_target: str | None = None
    append: bool = False
    stderr_to_stdout: bool = False
    # `2>&1 > file` binds stderr to the terminal that is stdout *at that point*,
    # so the error stays visible; `> file 2>&1` hides it. Order matters.
    stderr_merged_early: bool = False

    @property
    def any(self) -> bool:
        return bool(
            self.stdout_target
            or self.stderr_target
            or self.stdin_target
            or self.stderr_to_stdout
        )

    @property
    def hides_stdout(self) -> bool:
        return self.stdout_target is not None

    def targets(self) -> list[str]:
        """Every path this segment pointed I/O at, for intel.

        `/dev/null` included, and reads count too — `wc -l < /etc/shadow` says
        as much about intent as `id > /tmp/out` does.
        """
        out = []
        for target in (self.stdout_target, self.stderr_target, self.stdin_target):
            if target and target not in out:
                out.append(target)
        return out


def _split_tokens(segment: str) -> list[str]:
    """Whitespace-split one segment, keeping quoted runs together."""
    tokens, buf, quote = [], [], ""
    for ch in segment:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _split_operator(token: str) -> tuple[str | None, str]:
    """Split an attached operator from its target: `2>/dev/null` -> op, path."""
    for op in _OPERATORS:
        if token.startswith(op):
            return op, token[len(op):]
    return None, token


def parse_segment(segment: str) -> tuple[list[str], Redirect]:
    """Split one segment into pipeline stages plus the redirections applied.

    `2>&1` binds stderr to wherever stdout points at that moment, so
    `> file 2>&1` hides the error while `2>&1 > file` still shows it.
    """
    stages: list[list[str]] = [[]]
    red = Redirect()
    pending: str | None = None  # operator waiting for its target token

    for token in _split_tokens(segment):
        if pending is not None:
            _set_target(red, pending, token)
            pending = None
            continue

        if token == "<":
            pending = "<"
            continue
        if token.startswith("<") and not token.startswith("<<"):
            red.stdin_target = token[1:].strip("\"'")
            continue

        op, rest = _split_operator(token)
        if op is None:
            if token == "|":
                stages.append([])
            else:
                stages[-1].append(token)
            continue

        if op == "2>&1":
            red.stderr_to_stdout = True
            red.stderr_merged_early = red.stdout_target is None
            continue
        if rest:
            _set_target(red, op, rest)
        else:
            pending = op

    # A trailing operator with no target (`id >`) is simply dropped.
    stage_list = [" ".join(stage) for stage in stages if stage]
    head = stage_list[0].split()[0] if stage_list else ""
    if red.stdin_target and head in FILTERS:
        # `wc -l < f` reads f, which is exactly `cat f | wc -l` — reusing the
        # pipeline keeps one implementation of both the read and the filter.
        # Only filters read stdin this way; `id < f` just runs `id`.
        stage_list.insert(0, f"cat {red.stdin_target}")
    return stage_list, red


def _set_target(red: Redirect, op: str, target: str) -> None:
    target = target.strip("\"'")
    if op == "<":
        red.stdin_target = target
        return
    if op in ("&>", "&>>"):
        red.stdout_target = red.stderr_target = target
        red.append = op == "&>>"
    elif op in ("2>", "2>>"):
        red.stderr_target = target
        red.append = op == "2>>"
    else:  # >, >>, 1>, 1>>
        red.stdout_target = target
        red.append = op in (">>", "1>>")


def is_devnull(target: str | None) -> bool:
    return bool(target) and target.startswith(DEVNULL)


def split_streams(content: str, status: str) -> tuple[str, str]:
    """Split a command's output into (stdout, stderr).

    A non-zero status means the text is an error message, which bash writes to
    stderr — that is what makes `bogus 2>/dev/null` quiet while
    `bogus > /tmp/x` still shows the complaint.
    """
    if status != "0" and content:
        return "", content
    return content, ""


def visible_output(
    stdout_text: str, stderr_text: str, red: Redirect
) -> tuple[str, list[tuple[str, str]]]:
    """Decide what the attacker still sees and what gets written to a file.

    Returns (visible_text, [(target_path, text), ...]). `/dev/null` targets are
    dropped here and never reach the fake filesystem.
    """
    visible: list[str] = []
    writes: list[tuple[str, str]] = []

    if red.hides_stdout:
        if not is_devnull(red.stdout_target) and stdout_text:
            writes.append((red.stdout_target, stdout_text))
    else:
        visible.append(stdout_text)

    if red.stderr_to_stdout:
        # stderr follows stdout, wherever stdout pointed when they were merged.
        if red.hides_stdout and not red.stderr_merged_early:
            if not is_devnull(red.stdout_target) and stderr_text:
                writes.append((red.stdout_target, stderr_text))
        else:
            visible.append(stderr_text)
    elif red.stderr_target:
        if not is_devnull(red.stderr_target) and stderr_text:
            writes.append((red.stderr_target, stderr_text))
    else:
        visible.append(stderr_text)

    return "".join(visible), writes


def apply_filter(stage: str, text: str) -> tuple[str, str] | None:
    """Run a filter stage over piped text, or None if the stage isn't a filter.

    Status is the filter's own exit status, so `grep missing` reports 1 the way
    grep does.
    """
    parts = _split_tokens(stage)
    if not parts:
        return None
    name, args = parts[0], parts[1:]
    if name not in FILTERS:
        return None

    lines = text.splitlines()

    if name == "cat":
        return text, "0"

    if name == "grep":
        pattern = next((a for a in args if not a.startswith("-")), None)
        if pattern is None:
            return "", "2"
        try:
            rx = re.compile(_unquote(pattern), re.IGNORECASE if "-i" in args else 0)
        except re.error:
            return "", "2"
        invert = "-v" in args
        kept = [ln for ln in lines if bool(rx.search(ln)) != invert]
        if "-c" in args:
            return f"{len(kept)}\n", ("0" if kept else "1")
        return "".join(ln + "\n" for ln in kept), ("0" if kept else "1")

    if name in ("head", "tail"):
        count = 10
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                count = _int(args[i + 1], 10)
            elif a.startswith("-n"):
                count = _int(a[2:], 10)
            elif a.startswith("-") and a[1:].isdigit():
                count = _int(a[1:], 10)
        picked = lines[:count] if name == "head" else lines[-count:] if count else lines
        return "".join(ln + "\n" for ln in picked), "0"

    if name == "sort":
        if "-n" in args:
            out = sorted(lines, key=lambda s: float(s) if _isnum(s) else 0.0)
        else:
            out = sorted(lines)
        if "-r" in args:
            out = list(reversed(out))
        if "-u" in args:
            out = list(dict.fromkeys(out))
        return "".join(ln + "\n" for ln in out), "0"

    if name == "uniq":
        out, counts = [], []
        for ln in lines:
            if out and ln == out[-1]:
                counts[-1] += 1
            else:
                out.append(ln)
                counts.append(1)
        if "-c" in args:
            return "".join(f"{c:7d} {ln}\n" for ln, c in zip(out, counts)), "0"
        return "".join(ln + "\n" for ln in out), "0"

    if name == "cut":
        delim = " "
        fields = "1"
        for i, a in enumerate(args):
            if a.startswith("-d") and len(a) > 2:
                delim = _unquote(a[2:])
            elif a == "-d" and i + 1 < len(args):
                delim = _unquote(args[i + 1])
            elif a.startswith("-f") and len(a) > 2:
                fields = _unquote(a[2:])
            elif a == "-f" and i + 1 < len(args):
                fields = _unquote(args[i + 1])
        if len(delim) != 1:
            return "cut: the delimiter must be a single character\n", "1"
        idxs = [int(x) - 1 for x in fields.split(",") if x.strip().isdigit()]
        out = [
            delim.join(parts[i] if i < len(parts) else "" for i in idxs)
            for parts in (ln.split(delim) for ln in lines)
        ]
        return "".join(ln + "\n" for ln in out), "0"

    if name == "wc":
        if "-l" in args:
            return f"{len(lines)}\n", "0"
        if "-w" in args:
            return f"{len(text.split())}\n", "0"
        if "-c" in args:
            return f"{len(text.encode('utf-8'))}\n", "0"
        return (f"{len(lines)} {len(text.split())} "
                f"{len(text.encode('utf-8'))}\n"), "0"

    return None


def _unquote(token: str) -> str:
    """Drop the surrounding quotes a user typed: `-d' '` -> `-d `."""
    return token.strip("\"'")


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _isnum(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False
