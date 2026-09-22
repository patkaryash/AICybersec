"""FastAPI backend: thin HTTP adapter over agent_core.

The backend embeds agent_core in-process.  It owns HTTP concerns only -
composition (deps.py), routing (routes/) and SSE streaming.
"""
