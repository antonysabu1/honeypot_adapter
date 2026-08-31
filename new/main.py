import asyncio
import threading
import ssh_adapter.server as ssh_server
import telnet_adapter.server as telnet_server


def run_ssh():
    ssh_server.start_server()


def run_telnet():
    asyncio.run(telnet_server.start_server())


if __name__ == "__main__":
    print("=" * 50)
    print("Starting honeypot")
    print("  SSH    → port 2222")
    print("  Telnet → port 2323")
    print("  Logs   → logs/honeypot.jsonl")
    print("=" * 50)
    ssh_thread = threading.Thread(target=run_ssh, daemon=True)
    ssh_thread.start()
    run_telnet()