# backend/app/main.py

import hashlib
import json
import os
import shutil
import uuid

from backend.app import crud, models, schemas
from backend.app.database import engine, get_db
from backend.workers.tasks import run_analysis_pipeline
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

models.Base.metadata.create_all(bind=engine)
app = FastAPI(title="Malware Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "/home/jy/ghidra/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/upload/", response_model=schemas.Task)
async def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    magic_bytes = await file.read(2)
    await file.seek(0)
    if magic_bytes != b"MZ":
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a PE file (e.g., .exe, .dll).",
        )

    file_contents = await file.read()
    await file.seek(0)
    sha256_hash = hashlib.sha256(file_contents).hexdigest()

    cached_task = crud.get_completed_task_by_sha256(db, sha256=sha256_hash)

    # --- [핵심 수정 1] 캐시된 결과를 반환하기 전에 데이터를 재구성 ---
    if cached_task:
        print(f"[*] Cache hit for file: {file.filename} (SHA256: {sha256_hash})")

        # result_json 문자열을 파싱하여 result 객체로 변환
        result_data = (
            json.loads(cached_task.result_json) if cached_task.result_json else None
        )

        # Pydantic 스키마를 사용하여 응답 객체를 새로 만듦
        return schemas.Task(
            id=cached_task.id,
            status="SUCCESS (from Cache)",  # 상태를 캐시된 결과로 명시
            filename=cached_task.filename,
            sha256=cached_task.sha256,
            result=result_data,  # 파싱된 객체를 할당
            created_at=cached_task.created_at,
        )

    # --- 캐시가 없을 경우의 로직은 이전과 동일 ---
    print(f"[*] Cache miss. Starting new analysis for: {file.filename}")
    original_filename = file.filename
    _, file_extension = os.path.splitext(original_filename)
    safe_filename = f"{str(uuid.uuid4())}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    task_id = str(uuid.uuid4())
    db_task = crud.create_task(
        db, task_id=task_id, filename=original_filename, sha256=sha256_hash
    )
    run_analysis_pipeline.delay(file_path, task_id, "unknown", original_filename)
    return db_task


@app.get("/result/{task_id}", response_model=schemas.Task)
def get_result(task_id: str, db: Session = Depends(get_db)):
    db_task = crud.get_task(db, task_id)
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")

    # --- [핵심 수정 2] 폴링 시에도 동일한 로직으로 데이터 재구성 (일관성 유지) ---
    result_data = json.loads(db_task.result_json) if db_task.result_json else None

    return schemas.Task(
        id=db_task.id,
        status=db_task.status,
        filename=db_task.filename,
        sha256=db_task.sha256,
        result=result_data,
        created_at=db_task.created_at,
    )
