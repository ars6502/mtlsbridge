import typer
import yaml
import os
import subprocess
import sys
from pathlib import Path
from mitmproxy import http
from typing import Annotated

# ==============================================================================
# PART 1: MITM PROXY ADDON LOGIC
# This section is executed by the 'mitmdump' process when it imports this file.
# ==============================================================================

class DomainRewriteProxy:
    def __init__(self, config_path: str):
        self.mappings = self.load_config(config_path)

    def load_config(self, path):
        if not os.path.exists(path):
            print(f"❌ MITM Error: Config file {path} not found!")
            return {}
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
            # Create a dictionary: { "example1.test": 8080 }
            return {item['domain']: item['local_port'] for item in config.get('domains', [])}

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercepts the request:
        Changes destination to localhost:port and rewrites strings in body/headers.
        """
        host = flow.request.pretty_host
        if host in self.mappings:
            port = self.mappings[host]
            target = f"localhost:{port}"

            # 1. Redirect the network request to the local bridge
            flow.request.host = "127.0.0.1"
            flow.request.port = port

            # 2. Rewrite strings in Body and Headers
            search_str, replace_str = host.encode(), target.encode()

            if flow.request.content:
                flow.request.content = flow.request.content.replace(search_str, replace_str)

            for key, value in flow.request.headers.items():
                if search_str in value.encode():
                    flow.request.headers[key] = value.replace(host, target)

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Intercepts the response:
        Changes 'localhost:port' back to the original domain.
        """
        for domain, port in self.mappings.items():
            target = f"localhost:{port}"
            search_str, replace_str = target.encode(), domain.encode()

            # Rewrite Body
            if flow.response and flow.response.content:
                flow.response.content = flow.response.content.replace(search_str, replace_str)

            # Rewrite Headers
            if flow.response:
                for key, value in flow.response.headers.items():
                    if search_str in value.encode():
                        flow.response.headers[key] = value.replace(target, domain)

# THE GLUE: mitmproxy looks for the global 'addons' list.
# We read the config path from the environment variable set by the Typer CLI.
config_path_env = os.environ.get("MITM_CONFIG_PATH", "domain_map.yaml")
addons = [DomainRewriteProxy(config_path_env)]


# ==============================================================================
# PART 2: TYPER CLI WRAPPER
# This section is executed when you run 'mtls-rewrite' via uv.
# ==============================================================================


def command(
    config: Annotated[str,typer.Option(help="Path to domain mapping YAML")]="domain_map.yaml",
    port: Annotated[int, typer.Option( help="Port for the MITM proxy to listen on")]=8888,
):
    """
    Starts a MITM proxy that rewrites domain names to localhost ports.
    """

    config = Path(config)

    if not config.exists():
        typer.echo(f"❌ Config {config} not found", err=True)
        sys.exit(1)

    typer.echo(f"🛡️  Starting MITM Rewrite Proxy on port {port}...")
    typer.echo(f"Config: {config.absolute()}")
    typer.echo("Reminder: Set your system proxy to 127.0.0.1:8888 and install the mitmproxy CA cert.")
    typer.echo("-" * 60)

    # Prepare environment variables for the subprocess
    # This is how we pass the config path to the 'addons' list above
    env = os.environ.copy()
    env["MITM_CONFIG_PATH"] = str(config.absolute())

    # Launch mitmdump
    # -s: loads this file as a script
    # -p: sets the listen port
    cmd = [
        "mitmdump",
        "-s", __file__,
        "-p", str(port)
    ]

    try:
        subprocess.run(cmd, env=env, check=True)
    except KeyboardInterrupt:
        typer.echo("\n🛑 Proxy stopped.")
    except subprocess.CalledProcessError as e:
        typer.echo(f"❌ Proxy crashed: {e}", err=True)

def cli():
    typer.run(command)
