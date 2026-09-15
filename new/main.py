import asyncio
import os
import threading

import telnet_adapter.server as telnet_server

SSH_ADAPTER = os.environ.get("HONEYPOT_SSH_ADAPTER", "paramiko").strip().lower()

VALID_SSH_ADAPTERS = ("paramiko", "asyncssh")


async def _listen(name: str, start) -> bool:
    """Run one listener; its failure must never take down the others."""
    try:
        await start()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - a dead listener must not kill the rest
        print(f"  {name} listener failed: {exc!r}")
        return False
    return True


def run_paramiko_ssh():
    """Start the Paramiko listener; a bind failure must not print a traceback."""
    try:
        import ssh_adapter.server as ssh_server
        ssh_server.start_server()
    except Exception as exc:  # noqa: BLE001 - telnet must survive this thread dying
        print(f"  SSH/paramiko listener failed: {exc!r}")


async def run_telnet_and_asyncssh():
    """Telnet always runs; the experimental SSH transport is best-effort."""
    tasks = [asyncio.create_task(_listen("Telnet", telnet_server.start_server))]

    try:
        import asyncssh_adapter.server as asyncssh_server
    except ImportError:
        print("  SSH    -> disabled (asyncssh not installed)")
        print("            install with: pip install -r requirements-asyncssh.txt")
    else:
        tasks.append(asyncio.create_task(
            _listen("SSH/asyncssh", asyncssh_server.start_server)
        ))

    started = await asyncio.gather(*tasks)
    if not any(started):
        print("  no listeners started - exiting")
        raise SystemExit(1)


if __name__ == "__main__":
    print("=" * 50)
    print("Starting honeypot")
    print("  Telnet -> port 2323")
    print("  Logs   -> logs/honeypot.jsonl")

    if SSH_ADAPTER not in VALID_SSH_ADAPTERS:
        print(
            f"  HONEYPOT_SSH_ADAPTER={SSH_ADAPTER!r} is not one of "
            f"{VALID_SSH_ADAPTERS} - using the default (paramiko)"
        )

    if SSH_ADAPTER == "asyncssh":
        print("=" * 50)
        asyncio.run(run_telnet_and_asyncssh())
    else:
        print("  SSH    -> port 2222 (adapter: PARAMIKO)")
        print("=" * 50)
        ssh_thread = threading.Thread(target=run_paramiko_ssh, daemon=True)
        ssh_thread.start()
        asyncio.run(telnet_server.start_server())