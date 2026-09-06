from typing import List, Dict
from pydantic import BaseModel, Field

class ComplianceRequirement(BaseModel):
    id: str
    standard: str  # "IEC 62443", "NIST SP 800-82", "CISA CPG"
    code: str      # "FR 5", "AC-1", "CPG 2.A"
    title: str
    description: str
    target_score: int = 100
    actual_score: int = 0
    status: str = "Passed"  # Passed, Warning, Non-Compliant
    findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

class ComplianceScorecard(BaseModel):
    facility: str
    overall_score: float
    iec_62443_score: float
    nist_800_82_score: float
    cisa_cpg_score: float
    requirements: List[ComplianceRequirement] = Field(default_factory=list)
    summary: str
