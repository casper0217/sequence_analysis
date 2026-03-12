from celery import Celery

# [수정] main 이름을 프로젝트 루트에 맞게 설정
celery = Celery(
    "backend",  # 프로젝트 루트 이름
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# [수정] autodiscover_tasks를 사용하여 'backend' 패키지 내의 모든 tasks.py를 자동으로 찾음
celery.autodiscover_tasks(["backend.workers"])
