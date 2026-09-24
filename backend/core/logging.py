"""Application logging setup.

Rules:
- never log secrets: passwords, JWTs, API keys, AI provider keys,
  credentials, or authorization headers
- payloads that may contain secret-looking keys are scrubbed (reuse
  agent_core's scrub_secrets) before being written anywhere durable
- do not log full model prompts or raw scanner output by default
"""
from __future__ import annotations

import logging

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format=_LOG_FORMAT)
