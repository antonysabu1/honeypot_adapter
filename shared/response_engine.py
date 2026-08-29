from dataclasses import dataclass

from shared.filesystem import FakeFilesystem


@dataclass
class ResponsePlan:
    response_type: str
    content: str
    status: str


def decide_response(
    protocol: str,
    session_id: str,
    action: str,
    parameters: dict,
    fs: FakeFilesystem,
) -> ResponsePlan:
    command = action.strip()

    if action.strip().startswith("ls"):
        args = parameters.get("args", [])
        # Skip flags like -la, -a, -l
        path_args = [a for a in args if not a.startswith("-")]
        if path_args:
            path = path_args[0]
        else:
            path = parameters.get("cwd", "/")
        contents = fs.ls(path)
        content_str = "\n".join(contents) if contents else ""
        return ResponsePlan("directory_listing", content_str, "0")

    if command.startswith("cat "):
        args = parameters.get("args", [""])
        path = args[0] if args and args[0] else command[4:].strip()
        return ResponsePlan("file_contents", fs.cat(path), "0")

    if command == "pwd":
        return ResponsePlan("command_output", "/root", "0")

    if command == "whoami":
        return ResponsePlan("command_output", "root", "0")

    if command == "uname" or command.startswith("uname "):
        return ResponsePlan(
            "command_output",
            "Linux honeypot 5.15.0-105-generic "
            "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
            "0",
        )

    if command.startswith("cd "):
        return ResponsePlan("command_output", "", "0")

    if command == "exit":
        return ResponsePlan("session_end", "logout", "0")

    return ResponsePlan(
        "command_not_found",
        f"bash: {command}: command not found",
        "127",
    )