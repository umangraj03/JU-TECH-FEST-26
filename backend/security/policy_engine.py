import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import yaml
from backend.models.policy import PolicySchema, RuleDefinition
from backend.app.config import settings


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or settings.POLICY_FILE
        self.policy: PolicySchema = self._load_policy()

    def _load_policy(self) -> PolicySchema:
        path = Path(self.policy_path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return PolicySchema.model_validate(data)

    def reload(self):
        self.policy = self._load_policy()

    def update_policy_yaml(self, new_yaml_content: str) -> PolicySchema:
        """Validates new YAML before writing to disk."""
        data = yaml.safe_load(new_yaml_content)
        validated = PolicySchema.model_validate(data)
        with open(self.policy_path, "w", encoding="utf-8") as f:
            f.write(new_yaml_content)
        self.policy = validated
        return validated

    def get_raw_yaml(self) -> str:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            return f.read()

    def check_role_tool_allowed(self, role: str, tool_name: str) -> Tuple[bool, Optional[str]]:
        role_def = self.policy.roles.get(role)
        if not role_def:
            return False, f"Role '{role}' is not recognized by security policy."
        if tool_name not in role_def.allowed_tools:
            return False, f"Role '{role}' is not authorized to execute tool '{tool_name}'."
        return True, None

    def check_record_class_allowed(self, role: str, classification: str) -> Tuple[bool, Optional[str]]:
        role_def = self.policy.roles.get(role)
        if not role_def:
            return False, f"Role '{role}' is not recognized."
        if classification.lower() not in [c.lower() for c in role_def.accessible_record_classes]:
            return False, f"Role '{role}' cannot access '{classification}' classified records."
        return True, None

    def check_approved_destination(self, domain_or_url: str) -> Tuple[bool, Optional[str]]:
        """Exact registrable domain check against approved destinations."""
        clean = domain_or_url.lower().strip()
        # Remove scheme if present
        if "://" in clean:
            clean = clean.split("://", 1)[1]
        # Remove userinfo
        if "@" in clean:
            clean = clean.split("@")[-1]
        # Remove path and port
        clean = clean.split("/")[0].split(":")[0]

        for approved in self.policy.approved_destinations:
            if clean == approved.lower():
                return True, None

        return False, f"Destination domain '{clean}' is not on the approved destination allowlist: {self.policy.approved_destinations}"

    def check_tool_requires_approval(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        tool_def = self.policy.tools.get(tool_name)
        if not tool_def:
            return False, None

        if tool_def.requires_approval or tool_def.is_write:
            return True, f"Tool '{tool_name}' is classified as requiring human approval (is_write={tool_def.is_write})."

        return False, None


policy_engine = PolicyEngine()
