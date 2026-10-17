"""
Incident Report PDF Generator for VulnGraph.
============================================
Generates comprehensive, professional security incident PDF dossiers for
vulnerabilities triaged by VulnGraph autonomous agents.

Includes:
  - Executive Severity & Priority Inversion Matrix
  - FalkorDB Attack Path & Crown-Jewel Exploit Traversal
  - Service Blast Radius & Owning Team
  - Remediation Playbook (exact CLI upgrade commands & compensating controls)
  - Production Agentic Security Verification & SHA-256 Audit Hash
  - Human-in-the-Loop Approval Sign-Off Block
"""

import io
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from queries import get_finding_context, blast_radius, exploit_path, compute_risk, find_owner
from security_guardrails import run_agentic_security_audit
from remediation import generate_remediation_plan


def generate_incident_pdf(vuln_id: str) -> bytes:
    """
    Builds a PDF incident report in-memory and returns raw bytes.
    """
    # 1. Gather all graph context
    ctx = get_finding_context(vuln_id)
    risk = compute_risk(vuln_id)
    br = blast_radius(vuln_id)
    services = br.get("impacted_services", [])
    primary_svc = services[0] if services else "api-gateway"
    ep = exploit_path(primary_svc)
    owner = find_owner(primary_svc)

    packages_info = ctx.get("packages", [])
    if packages_info and isinstance(packages_info[0], dict):
        pkg_name = packages_info[0].get("name", "unknown")
        pkg_ver = packages_info[0].get("version", "unknown")
    else:
        pkg_name = "unknown"
        pkg_ver = "unknown"

    fix_ver = ctx.get("fix_version") or "latest-patched"

    # 2. Run agentic security audit
    evidence = risk.get("evidence_paths", [f"{primary_svc} vulnerable via {pkg_name}"])
    audit = run_agentic_security_audit(
        vuln_id=vuln_id,
        action_type=risk["verdict"],
        risk_score=risk["graph_risk_score"],
        services=services,
        packages=[pkg_name],
        evidence=evidence
    )

    # 3. Generate remediation plan
    remed = generate_remediation_plan(
        vuln_id=vuln_id,
        package_name=pkg_name,
        package_version=pkg_ver,
        fix_version=fix_ver,
        is_internet_exposed=ep.get("is_internet_exposed", False),
        impacted_services=services,
        risk_score=risk["graph_risk_score"]
    )

    # 4. Setup PDF Document
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    header_title = ParagraphStyle(
        'HeaderTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )

    sub_title = ParagraphStyle(
        'SubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=4
    )

    body_text = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    code_text = ParagraphStyle(
        'CodeText',
        parent=styles['Normal'],
        fontName='Courier-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#09090b')
    )

    story = []

    # Title & Header
    story.append(Paragraph("VULNGRAPH SECURITY INCIDENT DOSSIER", header_title))
    story.append(Paragraph(f"Autonomous Graph Triage & Forensic Audit Report • Ref: {vuln_id} • Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", sub_title))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#00e5ff'), spaceBefore=2, spaceAfter=10))

    # Priority Metric Callout Table
    verdict_badge_color = colors.HexColor('#dc2626') if risk["graph_risk_score"] >= 7.0 else (colors.HexColor('#d97706') if risk["graph_risk_score"] >= 4.0 else colors.HexColor('#16a34a'))

    summary_data = [
        [
            Paragraph("<b>Target Vulnerability:</b>", body_text),
            Paragraph(f"<b>{vuln_id}</b>", body_text),
            Paragraph("<b>Triage Verdict:</b>", body_text),
            Paragraph(f"<b><font color='{verdict_badge_color.hexval()}'>{risk['verdict'].upper()}</font></b>", body_text),
        ],
        [
            Paragraph("<b>CVSS Base Score:</b>", body_text),
            Paragraph(f"{risk['cvss_raw']:.1f} / 10.0 (Unadjusted)", body_text),
            Paragraph("<b>Graph Risk Score:</b>", body_text),
            Paragraph(f"<b>{risk['graph_risk_score']:.2f} / 10.0</b> (FalkorDB)", body_text),
        ],
        [
            Paragraph("<b>Affected Package:</b>", body_text),
            Paragraph(f"<code>{pkg_name}@{pkg_ver}</code>", body_text),
            Paragraph("<b>Recommended Fix:</b>", body_text),
            Paragraph(f"<code>{fix_ver}</code>", body_text),
        ],
        [
            Paragraph("<b>Owning Squad:</b>", body_text),
            Paragraph(f"<b>{owner.get('team', 'Unassigned')}</b>", body_text),
            Paragraph("<b>Public Ingress Exposure:</b>", body_text),
            Paragraph(f"<b>{'🔥 EXPOSED' if ep.get('is_internet_exposed') else '🛡️ PROTECTED'}</b>", body_text),
        ]
    ]

    t_summary = Table(summary_data, colWidths=[110, 160, 120, 150])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # Executive Overview
    story.append(Paragraph("1. Executive Summary & Graph-Aware Risk Rationale", section_heading))
    summary_expl = (
        f"Vulnerability <b>{vuln_id}</b> has a base CVSS score of <b>{risk['cvss_raw']:.1f}</b>. "
        f"However, FalkorDB multi-hop path traversal revealed an actual operational risk of <b>{risk['graph_risk_score']:.2f}</b>. "
        f"{'This finding has been ESCALATED because the affected package is reachable through public internet ingress and connects directly to high-sensitivity crown-jewel datastores.' if risk['graph_risk_score'] >= 7.0 else 'This finding has been DEPRIORITIZED because it resides in internal offline services with zero ingress path to sensitive crown jewels.'}"
    )
    story.append(Paragraph(summary_expl, body_text))
    story.append(Spacer(1, 8))

    # Attack Path & Blast Radius
    story.append(Paragraph("2. FalkorDB Attack Path & Crown-Jewel Exposure", section_heading))

    raw_ingress = ep.get("ingress_paths", [])
    if raw_ingress and isinstance(raw_ingress[0], list):
        ingress_display = " -> ".join(raw_ingress[0])
    elif raw_ingress and isinstance(raw_ingress[0], str):
        ingress_display = " -> ".join(raw_ingress)
    else:
        ingress_display = "No ingress reachable"

    path_data = [
        [Paragraph("<b>Topology Attribute</b>", body_text), Paragraph("<b>Graph Ground-Truth Finding</b>", body_text)],
        [Paragraph("Impacted Services", body_text), Paragraph(", ".join(services) if services else "None", body_text)],
        [Paragraph("Internet Ingress Path", body_text), Paragraph(ingress_display, body_text)],
        [Paragraph("Max Crown-Jewel Sensitivity", body_text), Paragraph(f"<b>{risk.get('max_data_sensitivity', 'None').upper()}</b>", body_text)],
        [
            Paragraph("Reachable DataStores", body_text),
            Paragraph(", ".join([f"{dp['datastore']} ({dp['sensitivity']})" for dp in ep.get("data_paths", [])]) if ep.get("data_paths") else "None", body_text)
        ]
    ]

    for idx, p in enumerate(risk.get("evidence_paths", [])[:3], 1):
        path_data.append([
            Paragraph(f"Attack Path #{idx}", body_text),
            Paragraph(f"<code>{p}</code>", code_text)
        ])

    t_path = Table(path_data, colWidths=[150, 390])
    t_path.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_path)
    story.append(Spacer(1, 10))

    # Remediation Playbook
    story.append(Paragraph("3. Prescriptive Remediation & Mitigation Playbook", section_heading))

    remed_data = [
        [Paragraph("<b>Remediation Step</b>", body_text), Paragraph("<b>Actionable Instruction / CLI Command</b>", body_text)],
        [Paragraph("Package Upgrade Command", body_text), Paragraph(f"<code>{remed['upgrade_command']}</code>", code_text)],
        [Paragraph("Dependency Verification", body_text), Paragraph(f"<code>{remed['audit_command']}</code>", code_text)],
        [Paragraph("Estimated Effort", body_text), Paragraph(f"<b>{remed['estimated_effort'].upper()}</b>", body_text)],
        [
            Paragraph("Compensating Controls", body_text),
            Paragraph("<br/>• ".join([""] + remed.get("compensating_controls", ["None required"])), body_text)
        ]
    ]

    t_remed = Table(remed_data, colWidths=[150, 390])
    t_remed.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_remed)
    story.append(Spacer(1, 10))

    # Agentic Security & Compliance Audit
    story.append(Paragraph("4. Production Agentic Security & Verification Log", section_heading))

    audit_data = [
        [Paragraph("<b>Verification Check</b>", body_text), Paragraph("<b>Status</b>", body_text), Paragraph("<b>Security Detail</b>", body_text)],
    ]
    for chk in audit["checks"]:
        st_color = colors.HexColor('#16a34a') if chk["passed"] else colors.HexColor('#dc2626')
        audit_data.append([
            Paragraph(chk["check"].replace("_", " ").title(), body_text),
            Paragraph(f"<b><font color='{st_color.hexval()}'>{'PASSED' if chk['passed'] else 'FLAGGED'}</font></b>", body_text),
            Paragraph(chk["detail"], body_text)
        ])

    audit_data.append([
        Paragraph("Cryptographic Provenance", body_text),
        Paragraph("<b><font color='#2563eb'>SHA-256</font></b>", body_text),
        Paragraph(f"<code>{audit['audit_hash']}</code>", code_text)
    ])

    t_audit = Table(audit_data, colWidths=[150, 80, 310])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_audit)
    story.append(Spacer(1, 12))

    # Human-in-the-Loop Sign-Off Block
    story.append(KeepTogether([
        Paragraph("5. Human-in-the-Loop Sign-Off & Governance Authorization", section_heading),
        Spacer(1, 4),
        Table([
            [
                Paragraph("<b>Reviewed & Approved By:</b> ___________________________", body_text),
                Paragraph("<b>Date:</b> _______________", body_text),
            ],
            [
                Paragraph("<b>SOC Incident Ticket Ref:</b> <code>tickets.jsonl</code>", body_text),
                Paragraph("<b>Action Status:</b> Staged (Pending / Approved)", body_text)
            ]
        ], colWidths=[340, 200], style=[
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ])
    ]))

    # Build PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
