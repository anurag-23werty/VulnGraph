"""
Remediation Specialist Module
=============================
Generates concrete, actionable remediation playbooks for triaged vulnerabilities:
  - Exact CLI upgrade commands for Python (pip) and Node.js (npm).
  - Compensating controls (WAF rules, ingress filtering) for internet-facing risks.
  - Blast-radius containment and rollback strategies.
"""

from typing import Dict, Any, List


def generate_remediation_plan(
    vuln_id: str,
    package_name: str,
    package_version: str,
    fix_version: str,
    is_internet_exposed: bool,
    impacted_services: List[str],
    risk_score: float
) -> Dict[str, Any]:
    """
    Builds a structured remediation playbook.
    """
    # Detect ecosystem
    is_npm = package_name.startswith("@") or package_name in ["express", "axios", "lodash", "jsonwebtoken", "cookie-parser", "helmet", "cors", "body-parser"]
    ecosystem = "npm" if is_npm else "pip"

    target_ver = fix_version if fix_version else "latest-patched"

    if ecosystem == "npm":
        upgrade_command = f"npm install {package_name}@{target_ver}"
        audit_command = f"npm audit --json"
    else:
        upgrade_command = f"pip install --upgrade '{package_name}>={target_ver}'"
        audit_command = f"pip-audit"

    # Compensating controls if internet exposed
    compensating_controls = []
    if is_internet_exposed:
        compensating_controls.append(
            f"Apply WAF rate-limiting and payload inspection rules on public ingress endpoints invoking {impacted_services[0] if impacted_services else 'gateway'}."
        )
        compensating_controls.append(
            "Temporarily restrict inbound CIDRs if active exploitation signatures are observed."
        )
    else:
        compensating_controls.append(
            "Service is internal/offline; zero internet ingress observed. Schedule routine patch window."
        )

    # Rollback strategy
    rollback_plan = f"Revert deployment to previous container digest/commit; lock dependency to {package_name}=={package_version} if regression occurs."

    # Estimated effort
    if len(impacted_services) > 3:
        effort = "Medium (Multi-service integration testing required)"
    else:
        effort = "Low (Single or dual-service deployment)"

    return {
        "vuln_id": vuln_id,
        "package_name": package_name,
        "current_version": package_version,
        "target_version": target_ver,
        "ecosystem": ecosystem,
        "upgrade_command": upgrade_command,
        "audit_command": audit_command,
        "compensating_controls": compensating_controls,
        "rollback_plan": rollback_plan,
        "estimated_effort": effort,
        "impacted_services": impacted_services
    }
