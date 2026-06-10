"""
BAR Regression Suite Runner
============================

Run this script before committing any change to main.
All tests must pass before merging.

Usage:
    python tests/regression/run_regression.py         # run all
    python tests/regression/run_regression.py -v      # verbose

Author: Rolan Lobo (RNR)
"""

import sys
import os
import unittest
from pathlib import Path

# Force UTF-8 output on Windows so emoji/unicode never crash the runner
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Make sure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def run():
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(Path(__file__).parent),
        pattern="test_*_baseline.py"
    )

    total = suite.countTestCases()
    print(f"\n{'='*60}")
    print(f"  BAR Regression Suite -- {total} guard tests")
    print(f"{'='*60}\n")

    verbosity = 2 if "-v" in sys.argv else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    if result.wasSuccessful():
        print(f"  PASS  ALL {result.testsRun} REGRESSION TESTS PASSED")
    else:
        print(f"  FAIL  FAILURES: {len(result.failures)}   ERRORS: {len(result.errors)}")
        print(f"  {result.testsRun - len(result.failures) - len(result.errors)}"
              f"/{result.testsRun} tests passed")
    print(f"{'='*60}\n")

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    run()
