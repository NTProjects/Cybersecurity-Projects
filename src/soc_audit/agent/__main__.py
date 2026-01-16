"""Entry point for soc_audit.agent module."""
from __future__ import annotations

import sys
from pathlib import Path

from soc_audit.agent.agent_main import AgentRunner


def main():
    """Main entry point for agent."""
    try:
        # Try to load config from default path
        config_path = Path("config/default.json")
        if not config_path.exists():
            print(f"[ERROR] Config file not found: {config_path}")
            print("[ERROR] Create config/default.json with agent.enabled=true")
            sys.exit(1)

        runner = AgentRunner(config_path)
        runner.run()
    except KeyboardInterrupt:
        print("\n[AGENT] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Agent failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
