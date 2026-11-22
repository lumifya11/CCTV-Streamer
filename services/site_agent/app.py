"""Site Agent Coordinator for Multi-Site Authorized Local Discovery and Outbound Telemetry."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from shared.audit import record_audit_event
from shared.database import DatabaseManager, get_db
from shared.models import utc_now_iso


class SiteAgentManager:
    """
    Manages remote Site Agents deployed inside authorized LAN/VLAN segments.
    Agents initiate outbound authenticated connections to the central Gateway
    so remote camera RTSP ports are never exposed to the public internet.
    """

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db = db or get_db()

    def register_agent(
        self,
        site_id: str,
        name: str,
        cert_fingerprint: Optional[str] = None,
        version: str = "1.1.0",
        actor: str = "owner",
    ) -> Dict[str, Any]:
        agent_id = f"agt-{uuid.uuid4().hex[:10]}"
        fp = cert_fingerprint or f"sha256:{hashlib.sha256(agent_id.encode()).hexdigest()[:32]}"
        now = utc_now_iso()
        self.db.execute(
            """
            INSERT INTO site_agents (
                agent_id, site_id, name, version, cert_fingerprint,
                status, last_heartbeat, created_at
            )
            VALUES (?, ?, ?, ?, ?, 'ONLINE', ?, ?)
            """,
            (agent_id, site_id, name.strip(), version, fp, now, now),
        )
        record_audit_event(
            action="SITE_AGENT_REGISTERED",
            target_type="SITE_AGENT",
            target_id=agent_id,
            actor=actor,
            actor_role="ADMIN",
            details={"site_id": site_id, "name": name, "cert_fingerprint": fp},
            db=self.db,
        )
        return {
            "agent_id": agent_id,
            "site_id": site_id,
            "name": name.strip(),
            "version": version,
            "cert_fingerprint": fp,
            "status": "ONLINE",
            "last_heartbeat": now,
            "created_at": now,
        }

    def list_agents(self, site_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if site_id:
            return self.db.fetchall(
                "SELECT * FROM site_agents WHERE site_id = ? ORDER BY created_at ASC",
                (site_id,),
            )
        return self.db.fetchall("SELECT * FROM site_agents ORDER BY created_at ASC")

    def record_heartbeat(self, agent_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM site_agents WHERE agent_id = ?", (agent_id,)
        )
        if not row or row["status"] == "REVOKED":
            return None
        now = utc_now_iso()
        self.db.execute(
            "UPDATE site_agents SET last_heartbeat = ?, status = 'ONLINE' WHERE agent_id = ?",
            (now, agent_id),
        )
        return self.db.fetchone(
            "SELECT * FROM site_agents WHERE agent_id = ?", (agent_id,)
        )

    def revoke_agent(self, agent_id: str, actor: str = "owner") -> bool:
        row = self.db.fetchone(
            "SELECT * FROM site_agents WHERE agent_id = ?", (agent_id,)
        )
        if not row:
            return False
        self.db.execute(
            "UPDATE site_agents SET status = 'REVOKED' WHERE agent_id = ?",
            (agent_id,),
        )
        record_audit_event(
            action="SITE_AGENT_REVOKED",
            target_type="SITE_AGENT",
            target_id=agent_id,
            actor=actor,
            actor_role="OWNER",
            db=self.db,
        )
        return True
