"""Defense configurations for the target agent."""

from redteam.target.agent import AgentConfig

# Naive config: no defenses
NAIVE_CONFIG = AgentConfig(
    mark_untrusted=False,
    tool_allowlist={"read_email", "send_email", "read_file", "query_db", "http_post"},
    email_domain_allowlist=set(),
    egress_filter=False,
    argument_validation=False,
)

# Guarded config: all defenses enabled
GUARDED_CONFIG = AgentConfig(
    mark_untrusted=True,
    tool_allowlist={"read_email", "send_email", "read_file", "query_db"},
    email_domain_allowlist={"example.com", "company.com"},
    egress_filter=True,
    argument_validation=True,
)

__all__ = ["NAIVE_CONFIG", "GUARDED_CONFIG", "AgentConfig"]
