from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any

from ...models.event import Event
from ...models.session import Session
from ...utils.logger import Logger


class CorrelationEngine:
    """Simple correlation engine that links events via shared entities (IPs) in a rolling time-window."""

    def __init__(self, time_window: int = 300):
        """
        Args:
            time_window: correlation window in seconds (default 5 min).
        """
        self.time_window = timedelta(seconds=time_window)
        self.logger = Logger().get_logger()

    def correlate(self, session: Session) -> List[Dict[str, Any]]:
        """Return list of correlated incident clusters."""
        # Build mapping IP -> events
        ip_index: Dict[str, List[Event]] = defaultdict(list)
        for ev_dict in session.timeline_events:
            try:
                ev = Event(
                    timestamp=ev_dict.get("timestamp"),
                    source=ev_dict.get("source", "unknown"),
                    category=ev_dict.get("category", "misc"),
                    description=ev_dict.get("description", ""),
                    data=ev_dict.get("data", {})
                )
            except Exception:
                continue
            for ip_field in ("src_ip", "dst_ip", "ip"):
                ip_val = ev.data.get(ip_field)
                if ip_val:
                    ip_index[ip_val].append(ev)

        # Cluster events per IP by time window
        incidents = []
        for ip, events in ip_index.items():
            events.sort(key=lambda e: e.timestamp)
            cluster = [events[0]]
            for ev in events[1:]:
                if ev.timestamp - cluster[-1].timestamp <= self.time_window:
                    cluster.append(ev)
                else:
                    incidents.append({"ip": ip, "events": [e.to_dict() for e in cluster]})
                    cluster = [ev]
            if cluster:
                incidents.append({"ip": ip, "events": [e.to_dict() for e in cluster]})
        self.logger.debug(f"Correlation produced {len(incidents)} incident clusters")
        return incidents 