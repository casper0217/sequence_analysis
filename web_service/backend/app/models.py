import datetime

from sqlalchemy import Column, DateTime, Index, String, Text

from .database import Base


class AnalysisTask(Base):
    __tablename__ = "analysis_tasks"

    # --- 컬럼 정의 ---
    id = Column(String, primary_key=True, index=True)
    filename = Column(String, index=True)

    # 일반 문자열로 정의하여 "SUCCESS (from Cache)" 등 유연한 상태 저장 가능
    status = Column(String(50), default="PENDING")

    # 캐시 조회를 위한 sha256 컬럼. 빠른 조회를 위해 index=True
    sha256 = Column(String(64), nullable=True, index=True)

    # 모든 분석 결과를 JSON 텍스트로 저장
    result_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
