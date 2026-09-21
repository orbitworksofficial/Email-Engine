from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class MetaLeadFormPayload(BaseModel):
    lead_id: Optional[str] = None
    leadgen_id: Optional[str] = None
    form_id: Optional[str] = None
    created_time: Optional[int] = None
    full_name: str
    email: str
    company_name: Optional[str] = None
    job_title: Optional[str] = None
    utm_campaign: Optional[str] = None


class LinkedInLeadPayload(BaseModel):
    lead_id: str
    form_id: Optional[str] = None
    full_name: str
    email: str
    company_name: Optional[str] = None
    job_title: Optional[str] = None
    utm_campaign: Optional[str] = None


class LinkedInIDOnlyPayload(BaseModel):
    lead_id: str
    form_id: Optional[str] = None
    requires_api_fetch: bool = True


class GoogleAdsLeadPayload(BaseModel):
    lead_id: Optional[str] = None
    gclid: Optional[str] = None
    full_name: str
    email: str
    company_name: Optional[str] = None
    utm_campaign: Optional[str] = None


class WebsiteLeadPayload(BaseModel):
    full_name: str
    email: str
    company_name: Optional[str] = None
    notes: Optional[str] = None
    utm_source: Optional[str] = "website"
    utm_medium: Optional[str] = "organic"
    utm_campaign: Optional[str] = None


class CalendlyWebhookPayload(BaseModel):
    event: str
    payload: Dict[str, Any]


class ResendEventPayload(BaseModel):
    type: str
    data: Dict[str, Any]


class EmailCopywritingSchema(BaseModel):
    subject: str = Field(..., description="High-converting email subject line")
    body_html: str = Field(..., description="1-on-1 personalized HTML body text")
    key_insights: List[str] = Field(default_factory=list, description="Audit insights extracted from lead context")
    confidence_score: float = Field(default=0.95, description="Model confidence score")


class StandardAPIResponse(BaseModel):
    status: str = "success"
    message: str
    data: Optional[Dict[str, Any]] = None
