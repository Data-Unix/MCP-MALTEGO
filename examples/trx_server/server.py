"""Servidor de transforms de ejemplo (solo localhost).

Uso:  uv run python examples/trx_server/server.py [--port 8080]
Luego copia config/transforms.example.toml a config/transforms.toml.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from maltego_trx.registry import mapping, register_transform_function
from maltego_trx.server import app
from transforms import ALL


def build_app():  # type: ignore[no-untyped-def]
    for transform in ALL:
        if transform not in mapping.values():
            register_transform_function(transform)
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    build_app()
    print("Transforms:", ", ".join(sorted(mapping)), file=sys.stderr)
    app.run(host="127.0.0.1", port=args.port)
