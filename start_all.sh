#!/bin/bash

# --- 1. 환경 설정 및 기존 프로세스 정리 ---
export PYTHONPATH="${PYTHONPATH}:$(pwd)/web_service"
source web_service/backend/venv/bin/activate

echo "[*] Cleaning up old processes..."
pkill -f celery
pkill -f uvicorn
# 프론트엔드 포트(3000)가 사용 중이면 죽이기
fuser -k 3000/tcp > /dev/null 2>&1

# --- 2. Docker 인프라 실행 (DB, Redis) ---
echo "[*] Starting Docker (Postgres, Redis)..."
sudo docker compose down --remove-orphans
sudo docker compose up -d

# DB가 켜질 때까지 잠시 대기
sleep 3

# --- 3. 백엔드 워커 실행 (Celery) ---
echo "[*] Starting Celery Worker..."
# -P solo 옵션으로 안정성 확보
nohup celery -A backend.workers.celery_app worker --loglevel=info -P solo > celery.log 2>&1 &

# --- 4. API 서버 실행 (FastAPI) ---
echo "[*] Starting FastAPI Backend (Port 8000)..."
nohup uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload > fastapi.log 2>&1 &

# --- 5. 프론트엔드 실행 (Next.js) ---
echo "[*] Starting Next.js Frontend (Port 3000)..."
cd web_service/frontend
# 의존성 설치 확인 (처음 한 번은 필요)
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run dev