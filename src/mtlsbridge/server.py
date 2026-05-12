import typer
import yaml
import subprocess
import signal
import sys
import os
from pathlib import Path
from typing import Annotated


def command(config: Annotated[str, typer.Option("--config", help="Path to server config YAML")] = "server_config.yaml"):
    config_file = Path(config)
    if not config_file.exists():
        typer.echo(f"❌ Config {config_file} not found", err=True)
        sys.exit(1)

    with open(config_file, 'r') as f:
        conf = yaml.safe_load(f)

    certs = conf.get("certificates", {})
    s_pem, ca_crt = certs.get("server_pem"), certs.get("ca_crt")

    if not s_pem or not ca_crt or not os.path.exists(s_pem) or not os.path.exists(ca_crt):
        typer.echo("❌ Server certificates missing", err=True)
        sys.exit(1)

    processes = []

    def stop_all(sig, frame):
        for p in processes: p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_all)

    typer.echo("🚀 Starting mTLS Server Proxies...")
    for item in conf.get("mappings", []):
        pub, loc, desc = item.get("public_port"), item.get("local_port"), item.get("description")
        cmd = ["socat", f"OPENSSL-LISTEN:{pub},cert={s_pem},cafile={ca_crt},verify=1,fork", f"TCP4:127.0.0.1:{loc}"]
        typer.echo(f"[mTLS] {desc}: {pub} -> {loc}")
        processes.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))

    while True: signal.pause()

def cli():
    typer.run(command)
