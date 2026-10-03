"""
NetMonitor Pro - Wi-Fi Security & 802.11 Deauth Attack Detector
Analyzes wireless management frames, deauth flooding, and 802.11w Protection (MFP).
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict

logger = logging.getLogger("netmonitor.wifi")

@dataclass
class DeauthAlert:
    """Alert record for 802.11 Deauthentication / Disassociation attack."""
    timestamp: str
    target_bssid: str
    target_client: str
    frame_type: str         # "Deauthentication" or "Disassociation"
    reason_code: int        # e.g., 7 (Class 3 frame received from nonassociated STA)
    rate_per_sec: float
    severity: str = "CRITICAL"
    mitigation: str = "Enable 802.11w Protected Management Frames (PMF / MFP) or upgrade to WPA3."
    cwe: str = "CWE-306 (Missing Authentication for Critical Function)"

@dataclass
class WifiAPStatus:
    """Wi-Fi Access Point security posture."""
    bssid: str
    ssid: str
    channel: int
    security_type: str       # WPA2-Personal, WPA3-SAE, Open
    mfp_required: bool       # 802.11w Management Frame Protection
    deauth_attack_detected: bool = False
    deauth_count_5s: int = 0

class WifiSecurityInspector:
    """Inspects 802.11 Wireless frames for security vulnerabilities & attack patterns."""

    def __init__(self, burst_threshold: int = 10, window_seconds: int = 5):
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        
        # Deauth event tracking: (bssid, client_mac) -> list of timestamps
        self._deauth_events: Dict[str, List[float]] = {}
        self._known_aps: Dict[str, WifiAPStatus] = {}
        self._alerts: List[DeauthAlert] = []
        self._last_alert_time: float = 0.0

    def inspect_80211_frame(self, frame_type: int, frame_subtype: int,
                            bssid: str, client_mac: str,
                            reason_code: int = 7, timestamp: float = None) -> Optional[DeauthAlert]:
        """
        Inspect an 802.11 frame for Deauth (Type 0 = Management, Subtype 12 = Deauth, 10 = Disassoc).
        Returns a DeauthAlert if a burst attack rate is detected.
        """
        if timestamp is None:
            timestamp = time.time()

        # Frame Type 0 = Management
        # Subtype 12 (0x0C) = Deauthentication, Subtype 10 (0x0A) = Disassociation
        is_deauth = (frame_type == 0 and frame_subtype in (10, 12))
        if not is_deauth:
            return None

        key = f"{bssid}:{client_mac}"
        if key not in self._deauth_events:
            self._deauth_events[key] = []

        now = timestamp
        self._deauth_events[key].append(now)
        self._deauth_events[key] = [t for t in self._deauth_events[key] if now - t <= self.window_seconds]

        event_count = len(self._deauth_events[key])
        rate_per_sec = event_count / self.window_seconds

        # Check if rate exceeds burst threshold
        if event_count >= self.burst_threshold:
            frame_name = "Deauthentication" if frame_subtype == 12 else "Disassociation"
            alert = DeauthAlert(
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                target_bssid=bssid,
                target_client=client_mac,
                frame_type=frame_name,
                reason_code=reason_code,
                rate_per_sec=round(rate_per_sec, 1),
                severity="CRITICAL" if rate_per_sec > 5 else "HIGH"
            )

            # Avoid duplicate alert within 5s
            if now - self._last_alert_time >= 5.0 or self._last_alert_time == 0.0:
                self._last_alert_time = now
                self._alerts.append(alert)
                logger.warning("802.11 %s FLOOD DETECTED! BSSID=%s Target=%s Rate=%.1f/s",
                               frame_name, bssid, client_mac, rate_per_sec)

                if bssid in self._known_aps:
                    self._known_aps[bssid].deauth_attack_detected = True
                    self._known_aps[bssid].deauth_count_5s = event_count

                return alert

        return None

    def register_access_point(self, bssid: str, ssid: str, channel: int,
                               security_type: str, mfp_required: bool) -> WifiAPStatus:
        """Register an Access Point and its 802.11w MFP status."""
        ap = WifiAPStatus(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            security_type=security_type,
            mfp_required=mfp_required
        )
        self._known_aps[bssid] = ap
        return ap

    def get_alerts(self) -> List[dict]:
        """Get all Deauth attack alerts."""
        return [
            {
                "timestamp": a.timestamp,
                "target_bssid": a.target_bssid,
                "target_client": a.target_client,
                "frame_type": a.frame_type,
                "reason_code": a.reason_code,
                "rate_per_sec": a.rate_per_sec,
                "severity": a.severity,
                "mitigation": a.mitigation,
                "cwe": a.cwe,
            }
            for a in reversed(self._alerts)
        ]

    def get_ap_security_posture(self) -> List[dict]:
        """Return AP security posture status."""
        result = []
        for bssid, ap in self._known_aps.items():
            result.append({
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "channel": ap.channel,
                "security_type": ap.security_type,
                "mfp_required": ap.mfp_required,
                "vulnerable_to_deauth": not ap.mfp_required,
                "under_attack": ap.deauth_attack_detected,
                "deauth_burst_rate": ap.deauth_count_5s,
            })
        return result
