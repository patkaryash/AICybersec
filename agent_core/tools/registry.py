"""ToolRegistry: the whitelist of tools an agent run may use.

Safety property: a Decision can only execute if its tool name is present
here.  The model cannot invent tools; the runtime cannot execute them.
"""
from __future__ import annotations

from agent_core.schemas.tools import ToolSpec
from agent_core.tools.base import Tool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name:
            raise ValueError("Tool must have a non-empty name")
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name!r}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        """Raise KeyError for unregistered tools (whitelist enforcement)."""
        if name not in self._tools:
            raise KeyError(
                f"Unknown tool {name!r}. Registered: {sorted(self._tools)}"
            )
        return self._tools[name]

    def has(self, name: str) -> bool:
        return name in self._tools

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self) -> list[ToolSpec]:
        """Model-facing specs for every registered tool."""
        return [tool.spec() for tool in self._tools.values()]
