"""Policy configuration — maps declared purposes to allowed tool envelopes.

A policy file declares which tools each purpose may invoke, and optionally
constrains parameter values. Everything not explicitly allowed is denied.

SCARE-Context scanning is configured at two levels:
  - Global `scare:` block sets defaults for all purposes
  - Per-purpose `scare_overrides:` narrows or widens for that purpose

AMBER-inbound defaults to quarantine (fleet consensus 2026-10-04).
Forward-with-warning is opt-in via `quarantine_on_amber_inbound: false`.
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class SCAREConfig:
    context_scan: bool = True
    outbound_scan: bool = True
    inbound_scan: bool = True
    quarantine_on_red: bool = True
    quarantine_on_amber_inbound: bool = True
    alert_on_amber: bool = True
    hard_ceiling_bytes: int = 10 * 1024 * 1024

    def resolve(self, overrides: Optional[dict] = None) -> "SCAREConfig":
        if not overrides:
            return self
        return SCAREConfig(
            context_scan=overrides.get("context_scan", self.context_scan),
            outbound_scan=overrides.get("outbound_scan", self.outbound_scan),
            inbound_scan=overrides.get("inbound_scan", self.inbound_scan),
            quarantine_on_red=overrides.get("quarantine_on_red", self.quarantine_on_red),
            quarantine_on_amber_inbound=overrides.get("quarantine_on_amber_inbound", self.quarantine_on_amber_inbound),
            alert_on_amber=overrides.get("alert_on_amber", self.alert_on_amber),
            hard_ceiling_bytes=overrides.get("hard_ceiling_bytes", self.hard_ceiling_bytes),
        )


@dataclass
class ToolConstraint:
    name: str
    allowed_params: dict[str, list[str]] = field(default_factory=dict)

    def matches_tool(self, tool_name: str) -> bool:
        return fnmatch.fnmatch(tool_name, self.name)

    def check_params(self, params: dict) -> tuple[bool, Optional[str]]:
        if not self.allowed_params:
            return True, None
        for param_name, allowed_values in self.allowed_params.items():
            actual = params.get(param_name)
            if actual is None:
                continue
            if not any(fnmatch.fnmatch(str(actual), pat) for pat in allowed_values):
                return False, f"param '{param_name}' value '{actual}' not in allowed set"
        return True, None


@dataclass
class PurposeEnvelope:
    purpose: str
    allowed_tools: list[ToolConstraint] = field(default_factory=list)
    description: str = ""
    scare_overrides: Optional[dict] = None

    def check(self, tool_name: str, params: dict) -> tuple[bool, Optional[str]]:
        for constraint in self.allowed_tools:
            if constraint.matches_tool(tool_name):
                return constraint.check_params(params)
        return False, f"tool '{tool_name}' not in envelope for purpose '{self.purpose}'"


@dataclass
class Policy:
    purposes: dict[str, PurposeEnvelope] = field(default_factory=dict)
    default_purpose: Optional[str] = None
    scare: SCAREConfig = field(default_factory=SCAREConfig)

    def get_envelope(self, purpose: str) -> Optional[PurposeEnvelope]:
        return self.purposes.get(purpose)

    def get_scare_config(self, purpose: Optional[str] = None) -> SCAREConfig:
        if purpose:
            env = self.purposes.get(purpose)
            if env and env.scare_overrides:
                return self.scare.resolve(env.scare_overrides)
        return self.scare

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        path = Path(path)
        with open(path) as f:
            raw = yaml.safe_load(f)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        scare_raw = raw.get("scare", {})
        scare = SCAREConfig(**{k: v for k, v in scare_raw.items() if k in SCAREConfig.__dataclass_fields__}) if scare_raw else SCAREConfig()

        purposes = {}
        for purpose_name, purpose_def in raw.get("purposes", {}).items():
            tools = []
            for tool_def in purpose_def.get("allowed_tools", []):
                if isinstance(tool_def, str):
                    tools.append(ToolConstraint(name=tool_def))
                else:
                    tools.append(ToolConstraint(
                        name=tool_def["name"],
                        allowed_params=tool_def.get("allowed_params", {}),
                    ))
            purposes[purpose_name] = PurposeEnvelope(
                purpose=purpose_name,
                allowed_tools=tools,
                description=purpose_def.get("description", ""),
                scare_overrides=purpose_def.get("scare_overrides"),
            )
        return cls(
            purposes=purposes,
            default_purpose=raw.get("default_purpose"),
            scare=scare,
        )
