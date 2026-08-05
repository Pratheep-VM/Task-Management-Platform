from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional
from models import PriorityEnum, StatusEnum

class TaskBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=150, example="Deploy Production API")
    description: Optional[str] = Field(None, example="Run database migrations and verify health checks.")
    category: str = Field(default="Engineering", max_length=50)
    priority: PriorityEnum = PriorityEnum.MEDIUM
    status: StatusEnum = StatusEnum.BACKLOG
    assigned_to: Optional[str] = Field(default="Unassigned", max_length=100)

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=150)
    description: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[PriorityEnum] = None
    status: Optional[StatusEnum] = None
    assigned_to: Optional[str] = None

class TaskResponse(TaskBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)