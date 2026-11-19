"""Allow running as `python -m docker_supply_lite`."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
