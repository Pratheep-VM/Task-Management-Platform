from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List
import models, schemas, crud, database

# Initialize Database Tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="Enterprise Task & Resource Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

templates = Jinja2Templates(directory="templates")

# ======================================================================
# WEB FRONTEND ROUTES (SSR Jinja2)
# ======================================================================

@app.get("/", response_class=HTMLResponse, tags=["Web UI"])
def render_dashboard(request: Request, db: Session = Depends(database.get_db)):
    tasks = crud.get_tasks(db)
    metrics = crud.get_dashboard_metrics(db)
    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"tasks": tasks, "metrics": metrics}
    )

# ======================================================================
# REST API ENDPOINTS (Full CRUD)
# ======================================================================

@app.get("/api/v1/tasks", response_model=List[schemas.TaskResponse], tags=["REST Tasks"])
def list_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    return crud.get_tasks(db, skip=skip, limit=limit)

@app.post("/api/v1/tasks", response_model=schemas.TaskResponse, status_code=status.HTTP_201_CREATED, tags=["REST Tasks"])
def create_new_task(task: schemas.TaskCreate, db: Session = Depends(database.get_db)):
    return crud.create_task(db, task)

@app.get("/api/v1/tasks/{task_id}", response_model=schemas.TaskResponse, tags=["REST Tasks"])
def retrieve_task(task_id: int, db: Session = Depends(database.get_db)):
    task = crud.get_task(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task with ID {task_id} not found.")
    return task

@app.put("/api/v1/tasks/{task_id}", response_model=schemas.TaskResponse, tags=["REST Tasks"])
def modify_task(task_id: int, task: schemas.TaskUpdate, db: Session = Depends(database.get_db)):
    updated_task = crud.update_task(db, task_id, task)
    if not updated_task:
        raise HTTPException(status_code=404, detail=f"Task with ID {task_id} not found.")
    return updated_task

@app.delete("/api/v1/tasks/{task_id}", status_code=status.HTTP_200_OK, tags=["REST Tasks"])
def remove_task(task_id: int, db: Session = Depends(database.get_db)):
    success = crud.delete_task(db, task_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Task with ID {task_id} not found.")
    return {"status": "success", "message": f"Task {task_id} deleted successfully."}

import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)