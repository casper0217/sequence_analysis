import json
from typing import Optional

from backend.app import models
from sqlalchemy.orm import Session


def create_task(
    db: Session, task_id: str, filename: str, sha256: str
) -> models.AnalysisTask:
    """
    새로운 분석 작업을 데이터베이스에 생성합니다.
    sha256 해시도 함께 저장합니다.
    """
    db_task = models.AnalysisTask(id=task_id, filename=filename, sha256=sha256)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


def get_task(db: Session, task_id: str) -> Optional[models.AnalysisTask]:
    """
    주어진 task_id로 작업을 조회합니다.
    """
    return (
        db.query(models.AnalysisTask).filter(models.AnalysisTask.id == task_id).first()
    )


def get_completed_task_by_sha256(
    db: Session, sha256: str
) -> Optional[models.AnalysisTask]:
    """
    주어진 sha256 해시를 가진, 'SUCCESS' 상태로 완료된 가장 최신 작업을 찾습니다.
    이 함수는 AnalysisTask 객체 또는 None을 반환해야 합니다.
    """
    return (
        db.query(models.AnalysisTask)
        .filter(models.AnalysisTask.sha256 == sha256)
        .filter(models.AnalysisTask.status == "SUCCESS")
        .order_by(models.AnalysisTask.created_at.desc())
        .first()
    )


def update_task_status(
    db: Session, status: str, task_id: str, result: Optional[dict] = None
) -> Optional[models.AnalysisTask]:
    """
    작업의 상태와 결과(선택사항)를 업데이트합니다.
    """
    db_task = get_task(db, task_id)
    if db_task:
        db_task.status = status
        if result:
            db_task.result_json = json.dumps(result)
        db.commit()
        db.refresh(db_task)
    return db_task
