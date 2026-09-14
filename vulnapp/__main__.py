"""Run the vulnerable app: ``python -m vulnapp``.

Environment:
  PORT          listen port (default 8000)
  HOST          bind host   (default 127.0.0.1)
  VULNAPP_SAFE  "1" -> hardened build (false-positive control)
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("vulnapp.app:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
