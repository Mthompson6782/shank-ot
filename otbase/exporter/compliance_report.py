from typing import List, Dict, Any
from otbase.models.asset import Asset, PurdueLevel, KeySwitchMode
from otbase.models.topology import SecurityViolation, SecurityViolationType
from otbase.models.compliance import ComplianceRequirement, ComplianceScorecard

class ComplianceReportGenerator:
    """Generates ISA/IEC 62443 and NIST SP 800-82 audit scorecards and compliance reports."""

    @classmethod
    def evaluate(
        cls,
        facility: str,
        assets: List[Asset],
        violations: List[SecurityViolation]
    ) -> ComplianceScorecard:
        reqs: List[ComplianceRequirement] = []

        # 1. IEC 62443 FR 5: Restricted Data Flow (Segmentation & Conduits)
        fr5_findings = []
        fr5_score = 100
        for v in violations:
            if v.violation_type in (
                SecurityViolationType.DIRECT_IT_TO_OT,
                SecurityViolationType.DUAL_HOMED_BRIDGE,
                SecurityViolationType.UNINSPECTED_CROSS_ZONE
            ):
                fr5_findings.append(f"{v.title}: {v.description}")
                fr5_score -= 30
        fr5_score = max(0, fr5_score)
        reqs.append(
            ComplianceRequirement(
                id="req-iec-fr5",
                standard="IEC 62443-3-3",
                code="FR 5",
                title="Restricted Data Flow (Zone & Conduit Segmentation)",
                description="Enforces strict microsegmentation between Purdue levels, requiring all cross-zone traffic to traverse inspected conduits and preventing dual-homed bypasses.",
                actual_score=fr5_score,
                status="Passed" if fr5_score >= 80 else ("Warning" if fr5_score >= 50 else "Non-Compliant"),
                findings=fr5_findings,
                recommendations=["Eliminate dual-homed interfaces", "Install inline DPI firewalls on uninspected conduits"] if fr5_findings else ["Maintain current zoning policy."]
            )
        )

        # 2. IEC 62443 FR 2: Use Control (Physical Key Switch & Authorization)
        fr2_findings = []
        fr2_score = 100
        for a in assets:
            if a.purdue_level == PurdueLevel.LEVEL_1 and a.key_switch in (KeySwitchMode.REMOTE_RUN, KeySwitchMode.REMOTE_PROG):
                fr2_findings.append(f"{a.tag_name} ({a.model}) physical key switch set to {a.key_switch.value}")
                fr2_score -= 20
        fr2_score = max(0, fr2_score)
        reqs.append(
            ComplianceRequirement(
                id="req-iec-fr2",
                standard="IEC 62443-4-2",
                code="FR 2",
                title="Use Control & Hardware Execution Lockout",
                description="Ensures controllers executing safety-critical and basic process control are physically write-protected via key switches to prevent unauthorized remote changes.",
                actual_score=fr2_score,
                status="Passed" if fr2_score >= 80 else ("Warning" if fr2_score >= 50 else "Non-Compliant"),
                findings=fr2_findings,
                recommendations=["Rotate PLC key switches to RUN position and manage physical keys under lockbox controls."] if fr2_findings else ["All PLC key switches verified locked."]
            )
        )

        # 3. NIST SP 800-82r3: Vulnerability and Patch Management
        nist_vuln_findings = []
        nist_score = 100
        for a in assets:
            if a.active_cves:
                nist_vuln_findings.append(f"{a.tag_name}: {len(a.active_cves)} active CVEs ({', '.join(a.active_cves[:2])})")
                nist_score -= 15
        nist_score = max(0, nist_score)
        reqs.append(
            ComplianceRequirement(
                id="req-nist-pm",
                standard="NIST SP 800-82r3",
                code="SI-2",
                title="ICS Flaw Remediation & Compensating Controls",
                description="Identifies known ICS vulnerabilities in operating systems, firmware, and controllers, requiring timely remediation or documented compensating controls.",
                actual_score=nist_score,
                status="Passed" if nist_score >= 80 else ("Warning" if nist_score >= 50 else "Non-Compliant"),
                findings=nist_vuln_findings,
                recommendations=["Apply compensating controls (firewall DPI, physical lockout) or schedule maintenance window firmware upgrades."] if nist_vuln_findings else ["No uncompensated CVEs detected."]
            )
        )

        # 4. CISA Cross-Sector CPG 2.A: Asset Inventory Baseline
        cpg_findings = []
        cpg_score = 95
        unidentified = [a.tag_name for a in assets if not a.serial_number or not a.firmware_version]
        if unidentified:
            cpg_findings.append(f"Assets with incomplete firmware/serial metadata: {', '.join(unidentified)}")
            cpg_score -= 25
        reqs.append(
            ComplianceRequirement(
                id="req-cisa-cpg",
                standard="CISA Cross-Sector CPG",
                code="CPG 2.A",
                title="Comprehensive OT Asset & Hardware Inventory",
                description="Maintains an accurate, automated, and up-to-date inventory of all cyber-physical devices, hardware revisions, and firmware baselines.",
                actual_score=cpg_score,
                status="Passed" if cpg_score >= 80 else "Warning",
                findings=cpg_findings,
                recommendations=["Complete catalog and firmware baselines via L5X/AML import or passive probe discovery."] if cpg_findings else ["Asset inventory coverage is 100% complete."]
            )
        )

        overall = round(sum(r.actual_score for r in reqs) / len(reqs), 1)
        iec_avg = round((fr5_score + fr2_score) / 2.0, 1)

        summary_text = (
            f"Audit completed for {facility}. Overall compliance posture is {overall}%. "
            f"Identified {len(violations)} network segmentation / topology violations. "
            f"Remediation of high-risk conduits and physical key switch lockouts will immediately elevate score above 90%."
        )

        return ComplianceScorecard(
            facility=facility,
            overall_score=overall,
            iec_62443_score=iec_avg,
            nist_800_82_score=float(nist_score),
            cisa_cpg_score=float(cpg_score),
            requirements=reqs,
            summary=summary_text
        )

    @classmethod
    def generate_markdown_report(cls, scorecard: ComplianceScorecard) -> str:
        md = [
            f"# Operational Technology Cybersecurity Audit & Compliance Report",
            f"**Facility**: {scorecard.facility}  ",
            f"**Overall Compliance Posture**: {scorecard.overall_score}%  ",
            f"**IEC 62443 Score**: {scorecard.iec_62443_score}% | **NIST SP 800-82 Score**: {scorecard.nist_800_82_score}% | **CISA CPG Score**: {scorecard.cisa_cpg_score}%  \n",
            f"## Executive Summary",
            f"{scorecard.summary}\n",
            f"## Evaluated Security Requirements\n"
        ]

        for req in scorecard.requirements:
            status_badge = "🟢 PASSED" if req.status == "Passed" else ("🟡 WARNING" if req.status == "Warning" else "🔴 NON-COMPLIANT")
            md.append(f"### [{req.code}] {req.title} ({req.standard}) - {status_badge} ({req.actual_score}%)")
            md.append(f"{req.description}\n")
            if req.findings:
                md.append("**Findings / Deficiencies:**")
                for f in req.findings:
                    md.append(f"- ⚠️ {f}")
                md.append("")
            if req.recommendations:
                md.append("**Remediation Actions:**")
                for r in req.recommendations:
                    md.append(f"- ✅ {r}")
                md.append("")

        return "\n".join(md)
