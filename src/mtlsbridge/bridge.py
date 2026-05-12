import typer
import yaml
import subprocess
import signal
import sys
import os
from pathlib import Path
from enum import Enum
from typing import Annotated

class BridgeMode(str, Enum):
    mtls = "mtls"
    transparent = "transparent"

def command(
    config: Annotated[str, typer.Option("--config", help="Path to client config YAML")] = "client_config.yaml",
    mode:   Annotated[str, typer.Option("--mode", help="Mode: mtls or transparent")] = BridgeMode.mtls
):

    bridge_mode = BridgeMode(mode)
    config_file = Path(config)
    if not config_file.exists():
        typer.echo(f"❌ Config {config_file} not found", err=True)
        sys.exit(1)

    with open(config_file, 'r') as f:
        conf = yaml.safe_load(f)

    server_ip = conf.get("server_address") or conf.get("server_ip")
    processes = []

    def stop_all(sig, frame):
        for p in processes: p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_all)

    if bridge_mode == BridgeMode.mtls:
        certs = conf.get("certificates", {})
        crt, key, ca = certs.get("client_crt"), certs.get("client_key"), certs.get("ca_crt")
        if not all([crt, key, ca, server_ip]):
            typer.echo("❌ Missing mTLS config/certs", err=True); sys.exit(1)

        typer.echo(f"🔌 Starting mTLS Bridge to {server_ip}...")
        for item in conf.get("mappings", []):
            loc, rem = item.get("local_port"), item.get("remote_port")
            cmd = ["socat", f"TCP4-LISTEN:{loc},reuseaddr,fork", f"OPENSSL:{server_ip}:{rem},cert={crt},key={key},cafile={ca},verify=0"]
            typer.echo(f"[mTLS] localhost:{loc} -> {server_ip}:{rem}")
            processes.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))

    else:
        typer.echo(f"🌐 Starting Transparent Bridge to {server_ip}...")
        for item in conf.get("mappings", []):
            loc, rem = item.get("local_port"), item.get("remote_port")
            cmd = ["socat", f"TCP4-LISTEN:{loc},reuseaddr,fork", f"TCP4:{server_ip}:{rem}"]
            typer.echo(f"[TCP] localhost:{loc} -> {server_ip}:{rem}")
            processes.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))

    while True: signal.pause()

def cli():
    typer.run(command)
