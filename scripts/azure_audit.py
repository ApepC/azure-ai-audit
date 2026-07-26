"""
azure_audit.py — Azure Infrastructure AI Security Auditor
==========================================================
Author: C Solo
GitHub: github.com/ApepC

Connects to a live Azure subscription, audits resources for
security misconfigurations, and uses the Anthropic Claude API
to generate plain-English remediation recommendations.

Checks:
    - NSGs: dangerous ports open to internet
    - Storage: public blob access, HTTP, TLS version
    - Key Vaults: soft delete, RBAC, network ACLs
    - VMs: managed identity, Trusted Launch
    - Resource Groups: tag compliance

Usage:
    az login
    python azure_audit.py
    python azure_audit.py --output report.json
    python azure_audit.py --subscription-id <SUB_ID>
"""

import argparse, json, os, sys
from datetime import datetime, timezone

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    import anthropic
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError as e:
    print(f"Missing dependency: {e}\nRun: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
REQUIRED_TAGS     = {"environment", "project", "owner", "managed_by"}
DANGEROUS_PORTS   = {22: "SSH", 3389: "RDP", 1433: "MSSQL",
                     5432: "PostgreSQL", 3306: "MySQL",
                     6379: "Redis", 27017: "MongoDB"}

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "PASS":     "green",
}

# ── Finding dataclass ────────────────────────────────────────
class Finding:
    def __init__(self, resource, category, severity, message, remediation=""):
        self.resource    = resource
        self.category    = category
        self.severity    = severity
        self.message     = message
        self.remediation = remediation
        self.ts          = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {k: getattr(self, k) for k in
                ["resource","category","severity","message","remediation","ts"]}

# ── AI remediation via Claude ────────────────────────────────
def get_ai_remediation(findings: list) -> str:
    """Send issues to Claude API for plain-English remediation summary."""
    if not ANTHROPIC_API_KEY:
        return "Set ANTHROPIC_API_KEY to enable AI-powered remediation advice."

    issues = [f"{f.severity}: {f.resource} — {f.message}"
              for f in findings if f.severity != "PASS"]
    if not issues:
        return "No issues found — infrastructure looks clean!"

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""You are an Azure cloud security expert. Below are security findings
from an automated audit. For each issue, provide a concise, plain-English
remediation step that a junior engineer can follow. Be specific and actionable.

Findings:
{chr(10).join(issues)}

Provide numbered remediation steps:"""

    message = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

# ── Audit: NSGs ──────────────────────────────────────────────
def audit_nsgs(cred, sub_id: str) -> list:
    findings = []
    client   = NetworkManagementClient(cred, sub_id)
    for nsg in client.network_security_groups.list_all():
        name = nsg.name or "unknown"
        for rule in (nsg.security_rules or []):
            if rule.access != "Allow" or rule.direction != "Inbound":
                continue
            src = rule.source_address_prefix or ""
            if src not in ("*", "Internet", "0.0.0.0/0", "Any"):
                continue
            ports = set()
            for pr in ([rule.destination_port_range] +
                       list(rule.destination_port_ranges or [])):
                if pr == "*":
                    ports.update(DANGEROUS_PORTS.keys())
                elif pr and "-" in pr:
                    lo, hi = pr.split("-")
                    ports.update(range(int(lo), int(hi)+1))
                elif pr:
                    try: ports.add(int(pr))
                    except ValueError: pass
            exposed = ports & set(DANGEROUS_PORTS.keys())
            if exposed:
                port_str = ", ".join(
                    f"{p}/{DANGEROUS_PORTS[p]}" for p in sorted(exposed))
                findings.append(Finding(
                    f"NSG: {name}", "Network", "CRITICAL",
                    f"Rule '{rule.name}' exposes {port_str} to Internet",
                    "Restrict source to a specific CIDR. Use Azure Bastion for admin access."
                ))
            else:
                findings.append(Finding(f"NSG: {name}", "Network", "PASS",
                                        f"Rule '{rule.name}' — no dangerous ports exposed"))
    return findings

# ── Audit: Storage ───────────────────────────────────────────
def audit_storage(cred, sub_id: str) -> list:
    findings = []
    client   = StorageManagementClient(cred, sub_id)
    for acct in client.storage_accounts.list():
        name = acct.name or "unknown"
        lbl  = f"Storage: {name}"

        sev = "HIGH" if acct.allow_blob_public_access else "PASS"
        findings.append(Finding(lbl, "Storage", sev,
            "Public blob access ENABLED" if sev == "HIGH" else "Public blob access disabled",
            "Set allowBlobPublicAccess=false." if sev == "HIGH" else ""))

        sev = "HIGH" if not acct.enable_https_traffic_only else "PASS"
        findings.append(Finding(lbl, "Storage", sev,
            "HTTP traffic allowed" if sev == "HIGH" else "HTTPS-only enforced",
            "Enable supportsHttpsTrafficOnly." if sev == "HIGH" else ""))

        tls = str(acct.minimum_tls_version or "TLS1_0")
        sev = "MEDIUM" if tls in ("TLS1_0","TLS1_1") else "PASS"
        findings.append(Finding(lbl, "Storage", sev,
            f"Minimum TLS: {tls}", "Set minimumTlsVersion=TLS1_2." if sev=="MEDIUM" else ""))

        nacl = acct.network_rule_set
        sev  = "HIGH" if not nacl or nacl.default_action == "Allow" else "PASS"
        findings.append(Finding(lbl, "Storage", sev,
            "Network ACL default=Allow (open to internet)" if sev == "HIGH"
            else "Network ACL default=Deny",
            "Set networkAcls.defaultAction=Deny with VNet rules." if sev=="HIGH" else ""))
    return findings

# ── Audit: Key Vaults ────────────────────────────────────────
def audit_key_vaults(cred, sub_id: str) -> list:
    findings = []
    client   = KeyVaultManagementClient(cred, sub_id)
    for vault in client.vaults.list():
        name  = vault.name or "unknown"
        lbl   = f"Key Vault: {name}"
        props = vault.properties

        sev = "HIGH" if not props.enable_soft_delete else "PASS"
        findings.append(Finding(lbl, "Key Vault", sev,
            "Soft delete DISABLED" if sev == "HIGH" else
            f"Soft delete enabled ({props.soft_delete_retention_in_days}d)",
            "Enable softDelete — cannot be disabled once set." if sev=="HIGH" else ""))

        sev = "MEDIUM" if not props.enable_rbac_authorization else "PASS"
        findings.append(Finding(lbl, "Key Vault", sev,
            "Using legacy access policies" if sev == "MEDIUM" else "RBAC authorization enabled",
            "Set enableRbacAuthorization=true for fine-grained control." if sev=="MEDIUM" else ""))

        nacl = props.network_acls
        sev  = "HIGH" if not nacl or nacl.default_action == "Allow" else "PASS"
        findings.append(Finding(lbl, "Key Vault", sev,
            "Network ACL allows all traffic" if sev == "HIGH" else "Network ACL=Deny",
            "Set networkAcls.defaultAction=Deny with VNet rules." if sev=="HIGH" else ""))
    return findings

# ── Audit: VMs ───────────────────────────────────────────────
def audit_vms(cred, sub_id: str) -> list:
    findings = []
    client   = ComputeManagementClient(cred, sub_id)
    for vm in client.virtual_machines.list_all():
        name = vm.name or "unknown"
        lbl  = f"VM: {name}"

        sev = "MEDIUM" if not vm.identity or vm.identity.type == "None" else "PASS"
        findings.append(Finding(lbl, "VM Security", sev,
            "No managed identity assigned" if sev == "MEDIUM"
            else f"Managed identity: {vm.identity.type}",
            "Assign System-Assigned managed identity." if sev=="MEDIUM" else ""))

        sec = vm.security_profile
        has_tl = sec and sec.uefi_settings and sec.security_type == "TrustedLaunch"
        sev = "LOW" if not has_tl else "PASS"
        findings.append(Finding(lbl, "VM Security", sev,
            "Trusted Launch not configured" if sev == "LOW" else "Trusted Launch enabled",
            "Set securityType=TrustedLaunch with SecureBoot+vTPM." if sev=="LOW" else ""))
    return findings

# ── Audit: Tags ──────────────────────────────────────────────
def audit_tags(cred, sub_id: str) -> list:
    findings = []
    client   = ResourceManagementClient(cred, sub_id)
    for rg in client.resource_groups.list():
        name    = rg.name or "unknown"
        existing = set((rg.tags or {}).keys())
        missing  = REQUIRED_TAGS - existing
        sev      = "MEDIUM" if missing else "PASS"
        findings.append(Finding(
            f"Resource Group: {name}", "Governance", sev,
            f"Missing tags: {', '.join(sorted(missing))}" if missing else "All required tags present",
            f"Add tags: {', '.join(sorted(missing))}" if missing else ""
        ))
    return findings

# ── Report ───────────────────────────────────────────────────
def print_report(findings: list, sub_id: str, ai_advice: str):
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]Azure AI Security Auditor[/bold cyan] — [dim]Author: CS[/dim]\n"
        f"[dim]Subscription: {sub_id}[/dim]\n"
        f"[dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
        border_style="cyan"
    ))

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_COLOR}
    summary = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    summary.add_column("Severity"); summary.add_column("Count", justify="right")
    for sev, color in SEV_COLOR.items():
        summary.add_row(f"[{color}]{sev}[/{color}]", str(counts.get(sev, 0)))
    console.print(summary)

    issues = [f for f in findings if f.severity != "PASS"]
    if issues:
        tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold white",
                    title="[bold]Findings[/bold]")
        tbl.add_column("Severity", no_wrap=True)
        tbl.add_column("Category", no_wrap=True)
        tbl.add_column("Resource", overflow="fold")
        tbl.add_column("Issue", overflow="fold")
        tbl.add_column("Remediation", overflow="fold", style="dim")
        for f in sorted(issues, key=lambda x: list(SEV_COLOR).index(x.severity)):
            c = SEV_COLOR[f.severity]
            tbl.add_row(f"[{c}]{f.severity}[/{c}]", f.category,
                        f.resource, f.message, f.remediation)
        console.print(tbl)

    console.print(Panel(f"[bold cyan]AI Remediation Advice (Claude)[/bold cyan]\n\n{ai_advice}",
                        border_style="cyan"))

# ── Main ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Azure AI Security Auditor — Author: CS")
    parser.add_argument("--subscription-id", help="Azure subscription ID")
    parser.add_argument("--output", help="Export JSON report to file")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI remediation")
    args = parser.parse_args()

    cred   = DefaultAzureCredential()
    sub_id = args.subscription_id
    if not sub_id:
        subs   = list(SubscriptionClient(cred).subscriptions.list())
        if not subs:
            console.print("[red]No Azure subscriptions found. Run 'az login'.[/red]")
            sys.exit(1)
        sub_id = subs[0].subscription_id

    console.print(f"[cyan]Auditing subscription: {sub_id}[/cyan]")
    all_findings = []
    for name, fn in [
        ("NSGs",         audit_nsgs),
        ("Storage",      audit_storage),
        ("Key Vaults",   audit_key_vaults),
        ("VMs",          audit_vms),
        ("Tags",         audit_tags),
    ]:
        console.print(f"  Scanning {name}...")
        all_findings.extend(fn(cred, sub_id))

    ai_advice = "" if args.no_ai else get_ai_remediation(all_findings)
    print_report(all_findings, sub_id, ai_advice)

    if args.output:
        data = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "subscription_id": sub_id,
            "total": len(all_findings),
            "summary": {s: sum(1 for f in all_findings if f.severity==s) for s in SEV_COLOR},
            "findings": [f.to_dict() for f in all_findings],
            "ai_remediation": ai_advice,
        }
        with open(args.output, "w") as fp:
            json.dump(data, fp, indent=2)
        console.print(f"[green]Report saved to: {args.output}[/green]")

if __name__ == "__main__":
    main()
