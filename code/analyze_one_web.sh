#!/bin/bash


# --- 1. 환경 설정 및 인자 받기 ---
INPUT_FILE_PATH="$1"   
LABEL="$2"             
ORIGINAL_FILENAME="$3" 

# [상대 경로 계산] 스크립트 위치 기준으로 프로젝트 루트(ghidra) 찾기
BASE_DIR=$(dirname "$(dirname "$(readlink -f "$0")")")

# .env 파일이 있으면 환경변수 로드 (GHIDRA_INSTALL_PATH 등)
if [ -f "${BASE_DIR}/.env" ]; then
    export $(grep -v '^#' "${BASE_DIR}/.env" | xargs)
fi

if [ -z "$GHIDRA_INSTALL_PATH" ]; then
    echo "---------------------------------------------------------------"
    echo "에러: GHIDRA_INSTALL_PATH 가 설정되지 않았습니다."
    echo ".env 파일에 기드라 설치 경로를 입력해주세요."
    echo "예: GHIDRA_INSTALL_PATH=/opt/ghidra_11.x"
    echo "---------------------------------------------------------------"
    exit 1
fi

# 환경변수에 값이 없으면 기본 경로 사용
GHIDRA_PATH="$GHIDRA_INSTALL_PATH"
GHIDRA_HEADLESS_PATH="${GHIDRA_PATH}/support/analyzeHeadless"

OUTPUT_DIR="${BASE_DIR}/json"
LOG_DIR="${BASE_DIR}/logs"
TEMP_DIR="${BASE_DIR}/temp"
GHIDRA_SCRIPTS_DIR="${BASE_DIR}/ghidra_scripts"
POST_SCRIPT="ultimate_analyzer.py"
DOTNET_ANALYZER_PATH="${BASE_DIR}/DotNetAnalyzer/bin/Release/net8.0/linux-x64/publish/DotNetAnalyzer"

# 디렉토리 생성 보장
mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$TEMP_DIR"

# --- 2. 임시 분석 폴더 설정 ---
TEMP_ANALYSIS_DIR="${TEMP_DIR}/analysis_$$_${RANDOM}"
mkdir -p "$TEMP_ANALYSIS_DIR"

ANALYSIS_TARGET="${TEMP_ANALYSIS_DIR}/${ORIGINAL_FILENAME}"
cp "$INPUT_FILE_PATH" "$ANALYSIS_TARGET"

JSON_BASENAME="${ORIGINAL_FILENAME%.*}"
OUTPUT_JSON="${OUTPUT_DIR}/${JSON_BASENAME}_analysis.json"
LOG_FILE="${LOG_DIR}/${JSON_BASENAME}.log"

# --- 3. 분석 실행 로직 ---

# .NET/Native 판별 (pefile 대신 strings로 간단히 판별하는 기존 로직 유지)
if strings "$INPUT_FILE_PATH" 2>/dev/null | head -100 | grep -qi "mscoree.dll"; then
    # .NET 분석기 실행
    timeout 60 "$DOTNET_ANALYZER_PATH" "$ANALYSIS_TARGET" "$OUTPUT_JSON" "$LABEL" > "$LOG_FILE" 2>&1 || true
else
    # Ghidra 분석기 실행
    TEMP_PROJECT="${TEMP_DIR}/proj_$$_${RANDOM}"
    mkdir -p "$TEMP_PROJECT"
    
    timeout 1800 "$GHIDRA_HEADLESS_PATH" \
        "$TEMP_PROJECT" "temp_project" \
        -import "$ANALYSIS_TARGET" -overwrite \
        -scriptPath "$GHIDRA_SCRIPTS_DIR" \
        -postScript "$POST_SCRIPT" "$OUTPUT_DIR" "$LABEL" \
        -analysisTimeoutPerFile 1800 \
        -deleteProject > "$LOG_FILE" 2>&1 || true
        
    rm -rf "$TEMP_PROJECT"
fi

# --- 4. 정리 및 결과 확인 ---
rm -rf "$TEMP_ANALYSIS_DIR"

if [ -f "$OUTPUT_JSON" ]; then
    exit 0 # 성공
else
    echo "Error: Output JSON was not created." >> "$LOG_FILE"
    exit 1 # 실패
fi