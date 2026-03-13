"""
PolicyProbe Agents Module

This module contains the multi-agent system for PolicyProbe:
- AgentOrchestrator: Routes requests between specialized agents
- TechSupportAgent: Handles general user queries (low privilege)
- FinanceAgent: Handles financial data queries (high privilege)
- FileProcessorAgent: Processes uploaded files
- DependencyResearchAgent: Looks up package info from registries
"""

from .orchestrator import AgentOrchestrator
from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .dependency_research import DependencyResearchAgent

__all__ = [
    "AgentOrchestrator",
    "TechSupportAgent",
    "FinanceAgent",
    "FileProcessorAgent",
    "DependencyResearchAgent",
]
