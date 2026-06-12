#!/usr/bin/env python3
"""
Abstract base class for all BugHunterPro scan modules.

Creating a plugin
-----------------
1. Subclass BaseModule
2. Set class attributes ``name`` and ``description``
3. Implement ``run(target: str) -> list``
4. Append dicts with at minimum::

     {"type": str, "severity": str, "detail": str}

   to ``self.results``, or return them from ``run()``.

5. Use ``self.errors`` to record non-fatal errors instead of raising.
6. Call ``execute(target)`` from the outside — it wraps ``run()`` with
   timing, error capture, and result storage.
"""

from abc import ABC, abstractmethod
from datetime import datetime


class BaseModule(ABC):
    name:        str = "base"
    description: str = "Base scan module"

    def __init__(self, config=None):
        self.config      = config or {}
        self.results     = []
        self.errors      = []
        self.started_at  = None
        self.finished_at = None

    @abstractmethod
    def run(self, target: str) -> list:
        """Execute the module against target. Return list of finding dicts."""

    def execute(self, target: str) -> list:
        """Timing wrapper — call this instead of run() from outside."""
        self.started_at = datetime.now()
        try:
            returned = self.run(target) or []
            if returned:
                self.results.extend(returned)
        except Exception as exc:
            self.errors.append(str(exc))
        finally:
            self.finished_at = datetime.now()
        return self.results

    def to_dict(self) -> dict:
        dur = None
        if self.started_at and self.finished_at:
            dur = round((self.finished_at - self.started_at).total_seconds(), 2)
        return {
            "module":      self.name,
            "description": self.description,
            "started_at":  self.started_at.isoformat() if self.started_at  else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_s":  dur,
            "results":     self.results,
            "errors":      self.errors,
        }
