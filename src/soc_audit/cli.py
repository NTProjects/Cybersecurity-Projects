"""Command-line interface for the SOC auditing framework."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from soc_audit.core.config import load_config
from soc_audit.core.engine import Engine
from soc_audit.reporting.reporter import ReportRenderer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOC auditing and intrusion detection framework")
    parser.add_argument(
        "-c",
        "--config",
        default="config/default.json",
        help="Path to JSON/YAML configuration file",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    engine = Engine(config)
    result = engine.run()
    renderer = ReportRenderer()
    if args.json:
        payload: dict[str, Any] = renderer.render_json(result)
        print(json.dumps(payload, indent=2))
    else:
        print(renderer.render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
