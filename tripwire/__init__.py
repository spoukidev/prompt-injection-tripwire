"""Prompt-Injection Tripwire: an interception proxy for tool-using LLM agents.

The proxy sits between an agent and its tools. It taints every tool result,
plants invisible canary tokens in it, and inspects every outgoing tool call for
signs that untrusted content is steering the agent (indirect prompt injection).

Public entry points:

* :class:`tripwire.engine.Tripwire` -- the in-process inspection engine.
* :mod:`tripwire.server` -- FastAPI app exposing ``/tool/{name}`` in front of tools.
"""

__version__ = "0.1.0"

from tripwire.engine import Tripwire  # noqa: E402,F401
