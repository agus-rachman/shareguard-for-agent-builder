# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Allow ``python -m absg``."""
import sys

from .core import main

sys.exit(main())
