"""agent_core: the pure agent foundation library.

Boundaries (approved architecture):
- no FastAPI / HTTP concerns in this package
- tools accessed ONLY via the Tool abstraction (no shell tool)
- model accessed ONLY via the ModelProvider protocol (no parsing here)
- everything runs offline with mocks; real tools/providers plug in later
  without changing this package's core.
"""
from agent_core.planner import Planner, ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink, PrinterSink
from agent_core.safety.policy import Policy, policy_from_env
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas import (
    AgentState,
    Decision,
    DangerLevel,
    Finding,
    Finish,
    Observation,
    RunStatus,
    StepRecord,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from agent_core.state import JsonFileStore, StateStore
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.registry import ToolRegistry

__all__ = [
    "AgentRuntime",
    "AgentState",
    "DangerLevel",
    "Decision",
    "Finding",
    "Finish",
    "InMemorySink",
    "JsonFileStore",
    "Observation",
    "Planner",
    "Policy",
    "PrinterSink",
    "RunStatus",
    "SafetyValidator",
    "ScriptedPlanner",
    "StateStore",
    "StepRecord",
    "Tool",
    "ToolCall",
    "ToolContext",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "policy_from_env",
]
