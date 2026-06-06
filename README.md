# Azure Infrastructure AI Security Auditor

**Author: CS** | [GitHub](https://github.com/ApepC)

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-SDK-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Anthropic](https://img.shields.io/badge/Claude-AI_Remediation-orange?style=for-the-badge)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Scheduled_Audit-2088FF?style=for-the-badge&logo=githubactions)

Connects to a live Azure subscription, audits resources for security misconfigurations,
and uses the **Anthropic Claude API** to generate plain-English AI-powered remediation advice.

---

## What It Audits

| Category | Checks |
|---|---|
| **NSG Rules** | Dangerous ports (SSH/RDP/SQL/Redis/MongoDB) open to Internet |
| **Storage Accounts** | Public blob access, HTTP allowed, TLS < 1.2, open network ACL |
| **Key Vaults** | Soft delete disabled, legacy access policies, open network ACL |
| **Virtual Machines** | No managed identity, Trusted Launch not configured |
| **Governance** | Missing required tags (`environment`, `project`, `owner`, `managed_by`) |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ApepC/azure-ai-audit.git
cd azure-ai-audit

# 2. Install
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Add ANTHROPIC_API_KEY to .env

# 4. Login to Azure
az login

# 5. Run audit
python scripts/azure_audit.py

# 6. Export JSON report
python scripts/azure_audit.py --output report.json

# 7. Skip AI advice
python scripts/azure_audit.py --no-ai
```

---

## Sample Output

```
╭──────────────────────────────────────────────────╮
│  Azure AI Security Auditor — Author: CSolo       │
│  Subscription: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx  │
│  2025-06-01 14:22 UTC                            │
╰──────────────────────────────────────────────────╯

┌──────────┬───────┐
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     1 │
│ HIGH     │     2 │
│ MEDIUM   │     1 │
│ PASS     │    18 │
└──────────┴───────┘

AI Remediation Advice (Claude):
1. For the NSG exposing port 22 to the Internet: Remove the
   allow-all inbound rule and deploy Azure Bastion for secure
   SSH/RDP access without exposing ports publicly...
```

---

## CI/CD — Scheduled Weekly Audit

The included GitHub Actions workflow runs every Monday at 8am UTC,
uploads an audit report as a pipeline artifact, and can be triggered
manually via `workflow_dispatch`.

**GitHub Secrets required:**
`AZURE_CREDENTIALS` · `ARM_SUBSCRIPTION_ID` · `ANTHROPIC_API_KEY`

---

## Project Structure

```
azure-ai-audit/
├── scripts/
│   └── azure_audit.py     # Main auditor: Azure SDK + Claude AI
├── .github/workflows/
│   └── audit.yml          # Scheduled weekly CI/CD audit
├── requirements.txt
├── .env.example
└── README.md
```

---

*Built by CSolo —*
