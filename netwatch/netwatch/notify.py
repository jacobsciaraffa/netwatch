"""Phone notifications via ntfy. Install the ntfy app, subscribe to your topic, done."""
import time
from collections import deque

import requests

_PRIORITY = {"high": "high", "medium": "default", "low": "low"}


class Notifier:
    def __init__(self, url, topic, click_url="", max_per_hour=20):
        self.url, self.topic, self.click_url = url, topic, click_url
        self.max_per_hour = max_per_hour
        self._sent = deque()
        self._suppressed = 0

    @property
    def enabled(self):
        return bool(self.topic)

    def send(self, title, message, severity="medium", tags="", _bypass=False):
        """title must be ASCII (it travels in an HTTP header). Returns True if sent."""
        if not self.enabled:
            return False
        now = time.time()
        while self._sent and now - self._sent[0] > 3600:
            self._sent.popleft()

        if not _bypass:
            if len(self._sent) >= self.max_per_hour:
                self._suppressed += 1
                if self._suppressed == 1:   # say so once, then stay quiet
                    self.send("netwatch: alert limit reached",
                              "Further alerts are saved to the dashboard only.",
                              "low", "mute", _bypass=True)
                return False
            self._suppressed = 0
            self._sent.append(now)

        headers = {"Title": title, "Priority": _PRIORITY.get(severity, "default")}
        if tags:
            headers["Tags"] = tags
        if self.click_url:
            headers["Click"] = self.click_url
        try:
            r = requests.post(f"{self.url}/{self.topic}",
                              data=message.encode("utf-8"), headers=headers, timeout=5)
            return r.ok
        except requests.RequestException as exc:
            print(f"[notify] failed: {exc}")
            return False
