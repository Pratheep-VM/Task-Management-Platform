from sqlalchemy.orm import Session
from sqlalchemy import select, func
import models, schemas

def get_tasks(db: Session, skip: int = 0, limit: int = 100):
    stmt = select(models.Task).order_by(models.Task.id.desc()).offset(skip).limit(limit)
    return db.scalars(stmt).all()

def get_task(db: Session, task_id: int):
    stmt = select(models.Task).where(models.Task.id == task_id)
    return db.scalars(stmt).first()

def create_task(db: Session, task: schemas.TaskCreate):
    db_task = models.Task(**task.model_dump())
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

def update_task(db: Session, task_id: int, task_data: schemas.TaskUpdate):
    db_task = get_task(db, task_id)
    if not db_task:
        return None
    
    update_dict = task_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(db_task, key, value)

    db.commit()
    db.refresh(db_task)
    return db_task

def delete_task(db: Session, task_id: int):
    db_task = get_task(db, task_id)
    if db_task:
        db.delete(db_task)
        db.commit()
        return True
    return False

def get_dashboard_metrics(db: Session):
    tasks = get_tasks(db)
    return {
        "total": len(tasks),
        "in_progress": len([t for t in tasks if t.status == models.StatusEnum.IN_PROGRESS]),
        "completed": len([t for t in tasks if t.status == models.StatusEnum.COMPLETED]),
        "critical": len([t for t in tasks if t.priority == models.PriorityEnum.CRITICAL])
    }