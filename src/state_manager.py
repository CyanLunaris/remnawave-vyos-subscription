"""
Persist nodes list and current node index to JSON files.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Optional

from .uri_parser import ParsedNode


class StateManager:
    def __init__(self, nodes_file: str, state_file: str):
        self._nodes_file = Path(nodes_file)
        self._state_file = Path(state_file)

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def save_nodes(self, nodes: List[ParsedNode]) -> None:
        self._nodes_file.parent.mkdir(parents=True, exist_ok=True)
        data = [n.to_dict() for n in nodes]
        self._nodes_file.write_text(json.dumps(data, indent=2))

    def load_nodes(self) -> List[ParsedNode]:
        if not self._nodes_file.exists():
            return []
        try:
            data = json.loads(self._nodes_file.read_text())
            return [ParsedNode(**d) for d in data]
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error("Failed to load nodes from %s: %s", self._nodes_file, exc)
            return []

    # ── State ─────────────────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        if not self._state_file.exists():
            return {"current_node": 0, "fail_count": 0}
        try:
            return json.loads(self._state_file.read_text())
        except Exception:
            return {"current_node": 0, "fail_count": 0}

    def _save_state(self, state: dict) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(json.dumps(state, indent=2))

    def get_current_index(self) -> int:
        return self._load_state().get("current_node", 0)

    def set_current_index(self, index: int) -> None:
        state = self._load_state()
        state["current_node"] = index
        self._save_state(state)

    def rotate_node(self) -> int:
        nodes = self.load_nodes()
        if not nodes:
            return 0
        new_idx = (self.get_current_index() + 1) % len(nodes)
        self.set_current_index(new_idx)
        return new_idx

    def get_current_node(self) -> Optional[ParsedNode]:
        nodes = self.load_nodes()
        if not nodes:
            return None
        idx = self.get_current_index() % len(nodes)
        return nodes[idx]

    def get_fail_count(self) -> int:
        return self._load_state().get("fail_count", 0)

    def increment_fail_count(self) -> int:
        state = self._load_state()
        state["fail_count"] = state.get("fail_count", 0) + 1
        self._save_state(state)
        return state["fail_count"]

    def reset_fail_count(self) -> None:
        state = self._load_state()
        state["fail_count"] = 0
        self._save_state(state)
