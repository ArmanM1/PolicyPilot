from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .models import RiskCategory


@dataclass(frozen=True)
class RiskAssessment:
    category: RiskCategory
    score: int
    signal: str


DESTRUCTIVE = re.compile(
    r"(?:\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)|\bremove-item\b.*\b-recurse\b|\bdel\s+/[sq]|\bformat\s+[a-z]:|\bmkfs\b|\bshred\b)",
    re.IGNORECASE,
)
CREDENTIAL = re.compile(
    r"(?:\.env\b|credentials?|secrets?\b|id_rsa|\.ssh[/\\]|keychain|aws_secret|private[_-]?key|browser.*cookie)",
    re.IGNORECASE,
)
NETWORK = re.compile(
    r"(?:\bcurl\b|\bwget\b|invoke-webrequest|invoke-restmethod|https?://|\bnc\s|netcat|fetch\s*\(|requests?\.(?:get|post))",
    re.IGNORECASE,
)
FORCE_PUSH = re.compile(r"\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f\b)", re.IGNORECASE)
SOURCE_MUTATION = re.compile(
    r"\bgit\s+(?:push|reset\s+--hard|clean\s+-f|rebase|branch\s+-D|tag\s+-d)\b",
    re.IGNORECASE,
)
DATABASE = re.compile(
    r"(?:\b(?:drop|truncate|delete\s+from|update\s+\w+\s+set|insert\s+into|alter\s+table)\b|\b(?:psql|mysql|sqlite3)\b.*\b(?:-c|--execute)\b)",
    re.IGNORECASE,
)
PACKAGE = re.compile(
    r"(?:\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\b|\b(?:pip|pip3)\s+install\b|\b(?:apt|apt-get|brew|choco)\s+install\b)",
    re.IGNORECASE,
)
BENIGN_READ = re.compile(
    r"^\s*(?:ls|dir|pwd|rg|grep|findstr|cat|type|get-content|git\s+(?:status|diff|log|show|branch)|python\s+--version|node\s+--version)\b",
    re.IGNORECASE,
)
BOUNDED_WRITE = re.compile(r"^\s*(?:touch|mkdir|new-item|copy-item|cp\s|echo\s|set-content)\b", re.IGNORECASE)


def assess_shell(command: str) -> RiskAssessment:
    compact = " ".join(command.strip().split())
    if not compact or "\x00" in compact:
        return RiskAssessment(RiskCategory.AMBIGUOUS_INVALID, 90, "empty or NUL-bearing command")
    if DESTRUCTIVE.search(compact):
        return RiskAssessment(RiskCategory.DESTRUCTIVE_FILESYSTEM, 100, "destructive filesystem signature")
    if CREDENTIAL.search(compact):
        return RiskAssessment(RiskCategory.CREDENTIAL_ACCESS, 100, "credential access signature")
    if FORCE_PUSH.search(compact):
        return RiskAssessment(RiskCategory.SOURCE_CONTROL_MUTATION, 95, "force-push signature")
    if DATABASE.search(compact):
        return RiskAssessment(RiskCategory.DATABASE_MUTATION, 85, "database mutation signature")
    if PACKAGE.search(compact):
        return RiskAssessment(RiskCategory.PACKAGE_INSTALL, 65, "package installation signature")
    if NETWORK.search(compact):
        return RiskAssessment(RiskCategory.NETWORK_EGRESS, 80, "outbound network signature")
    if SOURCE_MUTATION.search(compact):
        return RiskAssessment(RiskCategory.SOURCE_CONTROL_MUTATION, 75, "source-control mutation signature")
    if BENIGN_READ.search(compact):
        return RiskAssessment(RiskCategory.BENIGN_READ, 5, "read-only command allowlist")
    if BOUNDED_WRITE.search(compact):
        return RiskAssessment(RiskCategory.BOUNDED_WRITE, 35, "bounded write signature")
    return RiskAssessment(RiskCategory.AMBIGUOUS_INVALID, 70, "command is not classified by the safe fixture library")


def assess_mcp(server: str, tool_name: str, arguments: dict[str, Any], allowlisted_servers: set[str]) -> RiskAssessment:
    if server not in allowlisted_servers:
        return RiskAssessment(RiskCategory.UNTRUSTED_MCP, 95, "MCP server is not allowlisted")
    text = f"{tool_name} {json.dumps(arguments, sort_keys=True, default=str)}"
    lowered = tool_name.lower()
    if CREDENTIAL.search(text):
        return RiskAssessment(RiskCategory.CREDENTIAL_ACCESS, 100, "credential-bearing MCP action")
    if DESTRUCTIVE.search(text) or any(word in lowered for word in ("delete_tree", "recursive_delete", "destroy")):
        return RiskAssessment(RiskCategory.DESTRUCTIVE_FILESYSTEM, 100, "destructive MCP action")
    if DATABASE.search(text) or any(word in lowered for word in ("execute_sql", "mutate_database")):
        return RiskAssessment(RiskCategory.DATABASE_MUTATION, 85, "database mutation MCP action")
    if NETWORK.search(text) or any(word in lowered for word in ("http", "fetch", "send_webhook")):
        return RiskAssessment(RiskCategory.NETWORK_EGRESS, 80, "network-capable MCP action")
    if any(word in lowered for word in ("read", "list", "search", "inspect", "get_")):
        return RiskAssessment(RiskCategory.BENIGN_READ, 10, "read-only allowlisted MCP action")
    if any(word in lowered for word in ("write", "create", "update")):
        return RiskAssessment(RiskCategory.BOUNDED_WRITE, 40, "bounded MCP mutation")
    return RiskAssessment(RiskCategory.AMBIGUOUS_INVALID, 70, "unclassified MCP action")
