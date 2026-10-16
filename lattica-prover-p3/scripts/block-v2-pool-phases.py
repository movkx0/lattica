#!/usr/bin/env python3
"""Resume bounded native GPU pool services; output still requires audit/application."""
import argparse
from pathlib import Path

import block_v2_pool_phases as phases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--workflow', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    phases.run(phases.read(args.config), args.fixture, args.workflow, args.evidence)


if __name__ == '__main__':
    main()
