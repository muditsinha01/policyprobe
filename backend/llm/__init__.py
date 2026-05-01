"""
LLM Client Module

Provides clients for LLM communication.
"""


def _raise_not_approved(name):
    raise RuntimeError(
        f"{name} is not in the organization's approved LLM registry and cannot be used."
    )


__all__ = []