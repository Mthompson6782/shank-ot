from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field

class LifecycleState(str, Enum):
    ACTIVE = "Active (Fully Supported)"
    MATURE = "Mature (Available, Replacement Announced)"
    END_OF_LIFE = "End of Life (EOL - Sales Stopped)"
    END_OF_SUPPORT = "End of Support (EOS - No Security Patches)"
    DISCONTINUED = "Discontinued / Obsolete"

class LifecycleMilestone(BaseModel):
    model: str
    vendor: str
    release_year: int
    eol_year: Optional[int] = None
    eos_year: Optional[int] = None
    state: LifecycleState
    replacement_model: Optional[str] = None
    bulletin_url: Optional[str] = None
    description: Optional[str] = None

class ObsolescenceRisk(BaseModel):
    asset_id: str
    tag_name: str
    vendor: str
    model: str
    firmware_version: str
    state: LifecycleState
    urgency: str  # Critical, High, Medium, Low
    replacement_recommendation: str
    notes: Optional[str] = None
