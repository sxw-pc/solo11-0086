"""Root-path shim so ``python -m decodebench`` works before installation.

The installable package lives in ``src/decodebench``. This shim extends the
package search path and mirrors the small public constants from the real
package initializer.
"""

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "decodebench"
__path__ = [str(_SRC_PACKAGE), *list(globals().get("__path__", []))]
exec((_SRC_PACKAGE / "__init__.py").read_text(encoding="utf-8"), globals())
