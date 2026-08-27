class FakeFilesystem:
    def __init__(self) -> None:
        self._tree = {
            "etc": {
                "passwd": "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
                "shadow": "root::19840:0:99999:7:::\n"
                "daemon::19840:0:99999:7:::\n",
                "hosts": "127.0.0.1 localhost\n127.0.1.1 honeypot\n",
            },
            "var": {"www": {"html": {"index.html": "<html><body>"}}},
            "home": {"admin": {"notes.txt": "password123\n"}, "user": {}},
            "tmp": {},
            "bin": {},
            "usr": {"bin": {}},
        }

    def _resolve(self, path: str):
        parts = [part for part in path.split("/") if part != ""]
        node = self._tree
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    def exists(self, path: str) -> bool:
        return self._resolve(path) is not None

    def is_dir(self, path: str) -> bool:
        return isinstance(self._resolve(path), dict)

    def ls(self, path: str) -> list:
        node = self._resolve(path)
        if isinstance(node, dict):
            return sorted(node.keys())
        return []

    def cat(self, path: str) -> str:
        node = self._resolve(path)
        if node is None:
            return f"cat: {path}: No such file or directory"
        if isinstance(node, dict):
            return f"cat: {path}: Is a directory"
        return node