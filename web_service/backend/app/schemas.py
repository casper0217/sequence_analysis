# backend/app/schemas.py

import datetime
from typing import Any, Optional

from pydantic import BaseModel

# models.py에 있던 TaskStatus Enum은 삭제되었으므로,
# 여기서도 더 이상 import할 필요가 없습니다.


class Task(BaseModel):
    id: str

    # [수정] status의 타입을 Enum이 아닌 일반 문자열(str)로 받습니다.
    # 이렇게 하면 "SUCCESS (from Cache)" 와 같은 유연한 상태 값을 처리할 수 있습니다.
    status: str

    filename: str

    # [추가] sha256 필드를 API 응답에 포함시킵니다.
    # Optional[str] = None은 이 필드가 없을 수도 있다는 의미입니다. (예: 아주 오래된 데이터)
    sha256: Optional[str] = None

    # result와 created_at은 기존과 동일합니다.
    result: Optional[Any] = None
    created_at: datetime.datetime

    class Config:
        # DB 모델 객체(SQLAlchemy 모델)를 Pydantic 모델로 변환할 수 있게 해주는 설정입니다.
        from_attributes = True
