"""Native plugin scheduler for GODSEYE; no Docker or external worker."""
from __future__ import annotations
import logging
import threading
import time
from dataclasses import dataclass
from .plugins import Plugin, enabled_plugins
log = logging.getLogger("godseye.plugin_runner")

@dataclass
class PluginState:
    last_run: float | None = None
    last_success: float | None = None
    last_error: str | None = None
    running: bool = False

class PluginRunner:
    def __init__(self):
        self.states: dict[str, PluginState] = {}
        self._stop = threading.Event()

    def run_once(self, plugin: Plugin):
        state = self.states.setdefault(plugin.plugin_id, PluginState())
        if not plugin.run or not plugin.enabled or state.running:
            return False
        state.running = True
        state.last_run = time.time()
        try:
            plugin.run()
            state.last_success = time.time()
            state.last_error = None
            return True
        except Exception as exc:
            state.last_error = str(exc)
            log.exception("GODSEYE plugin %s failed", plugin.plugin_id)
            return False
        finally:
            state.running = False

    def run_forever(self, tick_seconds: int = 5):
        while not self._stop.wait(tick_seconds):
            now = time.time()
            for plugin in enabled_plugins():
                if plugin.schedule_seconds is None:
                    continue
                state = self.states.setdefault(plugin.plugin_id, PluginState())
                if state.last_run is None or now - state.last_run >= plugin.schedule_seconds:
                    threading.Thread(target=self.run_once, args=(plugin,), daemon=True).start()

    def start(self):
        thread = threading.Thread(target=self.run_forever, name="godseye-plugins", daemon=True)
        thread.start()
        return thread

    def stop(self):
        self._stop.set()

    def health(self):
        return {k: vars(v) for k, v in self.states.items()}
