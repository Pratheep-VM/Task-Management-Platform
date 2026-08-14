from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List
import os
from dotenv import load_dotenv
load_dotenv()



from mudraid_platform_middleware import MudraIDMiddleware
import models, schemas, crud, database

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Enterprise Task & Resource Platform", version="2.0.0")

# ======================================================================
# ATTACH MUDRAID MIDDLEWARE (GLOBAL REQUEST INTERCEPTION)
# ======================================================================
app.add_middleware(MudraIDMiddleware,
                    )

templates = Jinja2Templates(directory="templates")

# ======================================================================
# WEB FRONTEND & REST API ROUTES (No auth logic needed here!)
# ======================================================================

@app.get("/", response_class=HTMLResponse, tags=["Web UI"])
def render_dashboard(request: Request, db: Session = Depends(database.get_db)):
    tasks = crud.get_tasks(db)
    metrics = crud.get_dashboard_metrics(db)
    audit_logs = crud.get_audit_logs(db)
    return templates.TemplateResponse(request=request, name="index.html", context={"tasks": tasks, "metrics": metrics, "audit_logs": audit_logs})

@app.get("/api/v1/tasks", response_model=List[schemas.TaskResponse])
def list_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    return crud.get_tasks(db, skip=skip, limit=limit)

@app.post("/api/v1/tasks", response_model=schemas.TaskResponse, status_code=status.HTTP_201_CREATED)
def create_new_task(task: schemas.TaskCreate, db: Session = Depends(database.get_db)):
    return crud.create_task(db, task)

@app.put("/api/v1/tasks/{task_id}", response_model=schemas.TaskResponse)
def modify_task(task_id: int, task: schemas.TaskUpdate, db: Session = Depends(database.get_db)):
    return crud.update_task(db, task_id, task)

@app.delete("/api/v1/tasks/{task_id}")
def remove_task(task_id: int, db: Session = Depends(database.get_db)):
    return crud.delete_task(db, task_id)