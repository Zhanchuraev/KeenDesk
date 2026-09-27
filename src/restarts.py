"""Crash budget survives supervisor/router restart. Explicit start clears it."""
import json
import time
from common import CRASH, atomic_json

LIMIT = 5
WINDOW = 600


class Budget:
    def __init__(self, path=CRASH):
        self.path = path
        try: self.state = json.loads(path.read_text())
        except FileNotFoundError: self.state = {'events':[], 'halted':False}
        # Corrupt persistent state fails closed; it must not silently reset the budget.
        if not isinstance(self.state.get('events'),list) or not isinstance(self.state.get('halted'),bool):
            raise ValueError('Повреждён crash-state.json; выполните rustdeskctl restart')

    @property
    def halted(self): return self.state['halted']

    def failure(self, name, reason, now=None):
        now = time.time() if now is None else now
        events = [x for x in self.state['events'] if now-WINDOW <= x['time'] <= now]
        events.append({'time':now,'service':name,'reason':str(reason)[:200]})
        self.state = {'events':events, 'halted':len(events) >= LIMIT}
        atomic_json(self.path,self.state)
        return min(5 * 2**(len(events)-1),60)

    def stable(self):
        if self.state['events'] and not self.halted:
            self.state = {'events':[], 'halted':False}
            atomic_json(self.path,self.state)
