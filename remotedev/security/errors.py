from __future__ import annotations

try:  # mcp >= 2
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef]


class SecurityDenied(ToolError):
    def __init__(self, reason: str):
        super().__init__(f"ACCESS DENIED — {reason}")


class SecretDenied(SecurityDenied):
    def __init__(self) -> None:
        ToolError.__init__(self, "ACCESS DENIED — SECRET FILE")
