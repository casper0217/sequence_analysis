# backend/workers/tasks.py

import ast
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from subprocess import CalledProcessError

import joblib
import numpy as np
import requests
import torch
from backend.app import crud, models
from backend.app.database import SessionLocal
from backend.workers.celery_app import celery
from dotenv import load_dotenv
from transformers import BigBirdForSequenceClassification, BigBirdTokenizer

# ===================================================================
# 1. 모델, 경로 및 전역 변수 설정
# ===================================================================
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

BASE_DIR = str(Path(__file__).resolve().parents[3])


JSON_OUTPUT_DIR = os.path.join(BASE_DIR, "json")
DFS_SCRIPT_PATH = os.path.join(BASE_DIR, "code", "dfs_preprocessor.py")
SINGLE_ANALYSIS_SCRIPT_PATH = os.path.join(BASE_DIR, "code", "analyze_one_web.sh")
PE_EXTRACTOR_SCRIPT = os.path.join(BASE_DIR, "code", "live_pe_extractor.py")

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    print("[!] Warning: VT_API_KEY not found in enviroment variables.")

# --- 모델 경로 ---
MODEL_PATH = os.path.join(BASE_DIR, "models", "bigbird_from_scratch_best")
PE_MODEL_PATH = os.path.join(BASE_DIR, "models", "pro_best_detector_lightgbm.joblib")

# --- 전역 변수 초기화 ---
tokenizer, model = None, None
pe_model_details, pe_model, FINAL_PE_FEATURE_COLUMNS = None, None, []

# --- 모델 로드 로직 ---
try:
    if os.path.isdir(MODEL_PATH):
        tokenizer = BigBirdTokenizer.from_pretrained(MODEL_PATH)
        model = BigBirdForSequenceClassification.from_pretrained(MODEL_PATH)
        model.to(DEVICE)
        model.eval()
        print("[*] BigBird model and tokenizer loaded successfully.")
except Exception as e:
    print(f"[!] CRITICAL: Failed to load BigBird model. Error: {e}")

try:
    if os.path.exists(PE_MODEL_PATH):
        pe_model_details = joblib.load(PE_MODEL_PATH)
        pe_model = pe_model_details["model"]
        FINAL_PE_FEATURE_COLUMNS = pe_model_details["columns"]
        print(
            f"[*] PE feature model '{pe_model_details.get('name', 'N/A')}' loaded successfully."
        )
    else:
        print(f"[!] CRITICAL: PE model not found: {PE_MODEL_PATH}.")
except Exception as e:
    print(f"[!] CRITICAL: Failed to load PE model. Error: {e}")


# ===================================================================
# 2. 헬퍼 함수들
# ===================================================================
def convert_trace_to_hierarchical_sequence(trace_data) -> list:
    try:
        trace_list = (
            ast.literal_eval(str(trace_data))
            if isinstance(trace_data, str)
            else trace_data
        )
    except (ValueError, SyntaxError):
        trace_list = []
    if not isinstance(trace_list, list):
        return []
    final_sequence, call_stack = [], []
    for item in trace_list:
        if not isinstance(item, dict):
            continue
        func_name, current_depth = item.get("name", "unknown"), item.get("depth", -1)
        while call_stack and call_stack[-1][1] >= current_depth:
            ended_func, _ = call_stack.pop()
            final_sequence.append(f"FUNC_END::{ended_func}")
        if item.get("type") == "reference":
            continue
        final_sequence.append(f"FUNC_START::{func_name}")
        call_stack.append((func_name, current_depth))
        apis = item.get("apis", [])
        if isinstance(apis, list):
            for api in apis:
                final_sequence.append(f"API::{api}")
    while call_stack:
        ended_func, _ = call_stack.pop()
        final_sequence.append(f"FUNC_END::{ended_func}")
    return final_sequence


def prepare_pe_features_for_model(features: dict):
    if not features or not FINAL_PE_FEATURE_COLUMNS:
        return None
    try:
        feature_vector = [features.get(col, 0) for col in FINAL_PE_FEATURE_COLUMNS]
        return np.array(feature_vector).reshape(1, -1)
    except:
        return None


# ===================================================================
# 3. 실제 분석을 수행하는 Celery Task
# ===================================================================
@celery.task(name="run_analysis_pipeline")
def run_analysis_pipeline(
    filepath: str, task_id: str, label: str, original_filename: str
):
    db = SessionLocal()
    crud.update_task_status(db, "STARTED", task_id)
    final_result = {}

    try:
        # --- Stage 1 & 2: Ghidra/DFS 분석 ---
        crud.update_task_status(db, "Analyzing with Ghidra/DotNet...", task_id)
        json_basename = os.path.splitext(original_filename)[0]
        output_json_path = os.path.join(
            JSON_OUTPUT_DIR, f"{json_basename}_analysis.json"
        )
        dfs_output_path = output_json_path.replace(".json", "_dfs.json").replace(
            "/json/", "/json_dfs/"
        )
        subprocess.run(
            ["bash", SINGLE_ANALYSIS_SCRIPT_PATH, filepath, label, original_filename],
            check=True,
        )
        crud.update_task_status(db, "Preprocessing execution trace...", task_id)
        subprocess.run(
            ["python3", DFS_SCRIPT_PATH, output_json_path, "-o", dfs_output_path],
            check=True,
        )

        # --- Stage 2.1: 파일 기본 속성 추출 ---
        crud.update_task_status(db, "Extracting file properties...", task_id)
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_size = os.path.getsize(filepath)
        with open(output_json_path, "r") as f:
            analysis_data = json.load(f)

        final_result["file_properties"] = {
            "md5": analysis_data.get("md5", "N/A"),
            "sha256": sha256_hash.hexdigest(),
            "size_kb": round(file_size / 1024, 2),
            "type": analysis_data.get("file_type", "unknown"),
        }

        # --- Stage 2.2: VirusTotal 조회 ---
        crud.update_task_status(db, "Querying VirusTotal...", task_id)
        vt_result = {"detection_ratio": "N/A", "link": ""}
        if VT_API_KEY and VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY":
            headers = {"x-apikey": VT_API_KEY}
            sha256 = final_result["file_properties"]["sha256"]
            try:
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers=headers,
                    timeout=15,
                )
                if response.status_code == 200:
                    stats = (
                        response.json()
                        .get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values())
                    vt_result["detection_ratio"] = (
                        f"{positives} / {total}" if total > 0 else "0 / 0"
                    )
                elif response.status_code == 404:
                    vt_result["detection_ratio"] = "Not found"
                vt_result["link"] = f"https://www.virustotal.com/gui/file/{sha256}"
            except requests.RequestException:
                vt_result["detection_ratio"] = "API Error"
        final_result["virustotal"] = vt_result

        # --- Stage 2.5: PE 특징 추출 ---
        crud.update_task_status(db, "Analyzing PE structure...", task_id)
        proc = subprocess.run(
            ["python3", PE_EXTRACTOR_SCRIPT, filepath],
            check=True,
            capture_output=True,
            text=True,
        )
        pe_features = json.loads(proc.stdout)

        # --- Stage 3: 시퀀스 생성 및 API 요약 ---
        crud.update_task_status(db, "Generating behavioral sequence...", task_id)
        with open(dfs_output_path, "r") as f:
            dfs_data = json.load(f)
        final_result["unified_sequence"] = dfs_data.get("unified_sequence", [])
        execution_trace = dfs_data.get("execution_trace", [])
        sequence_tokens = convert_trace_to_hierarchical_sequence(execution_trace)
        sequence_text = " ".join(sequence_tokens)

        SUSPICIOUS_API_INFO = {
            "CreateRemoteThread": "Injects code into other processes, a classic malware technique.",
            "WriteProcessMemory": "Modifies the memory of another process, often used with injection.",
            "VirtualAlloc": "Allocates memory, which can be used to hold malicious shellcode.",
            "SetWindowsHookEx": "Installs a hook to monitor system-wide events like keystrokes.",
            "GetAsyncKeyState": "Checks the status of keys, commonly used for keylogging.",
            "URLDownloadToFile": "Downloads a file from the internet, often a next-stage payload.",
            "WinExec": "Executes another program without user consent.",
            "ShellExecute": "Opens or executes files, which can be used to run malicious scripts.",
            "RegCreateKey": "Creates or opens a registry key, often for persistence.",
            "RegSetValue": "Sets a value in the registry, used to alter system settings or maintain persistence.",
            "CryptEncrypt": "Encrypts data, a core component of ransomware.",
        }
        all_apis = {
            token.split("::")[-1]
            for token in sequence_tokens
            if token.startswith("API::")
        }
        found_suspicious_with_desc = []
        for api in sorted(list(all_apis)):
            for name, desc in SUSPICIOUS_API_INFO.items():
                if name in api:
                    found_suspicious_with_desc.append(
                        {"name": api, "description": desc}
                    )
                    break
        common_calls = sorted(
            list(all_apis - {item["name"] for item in found_suspicious_with_desc})
        )[:10]
        final_result["api_summary"] = {
            "suspicious_calls": found_suspicious_with_desc,
            "common_calls_sample": common_calls,
        }

        # --- Stage 4 & 4.5: 모델 추론 ---
        crud.update_task_status(db, "Running AI model inferences...", task_id)
        print(f"[{task_id}] Stage 4: Running model inferences...")
        dynamic_result = {}
        if model and tokenizer and sequence_text:
            inputs = tokenizer(
                sequence_text,
                return_tensors="pt",
                max_length=2048,
                truncation=True,
                padding="max_length",
            )
            inputs = {key: val.to(DEVICE) for key, val in inputs.items()}
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                probabilities = torch.nn.functional.softmax(logits, dim=-1).squeeze()
                prediction_idx = torch.argmax(probabilities).item()
                confidence = probabilities[prediction_idx].item()
            dynamic_result = {
                "prediction": "malware" if prediction_idx == 1 else "benign",
                "confidence": round(confidence * 100, 2),
            }
        elif not (model and tokenizer):
            # 모델 자체가 로드되지 않은 경우
            dynamic_result = {
                "prediction": "unknown",
                "confidence": 0.0,
                "reason": "Behavioral model not loaded.",
            }
        else:
            # API 시퀀스가 비어있어 분석이 불가능한 경우
            dynamic_result = {
                "prediction": "N/A",
                "confidence": 0.0,
                "reason": "No behavioral data (API sequence) to analyze.",
            }
        final_result["dynamic_analysis_result"] = dynamic_result

        pe_feature_result = {}
        if pe_model and pe_features:
            model_input = prepare_pe_features_for_model(pe_features)
            if model_input is not None:
                prediction_idx = int(pe_model.predict(model_input)[0])
                probabilities = pe_model.predict_proba(model_input)[0]
                confidence = probabilities[prediction_idx]
                pe_feature_result = {
                    "prediction": "malware" if prediction_idx == 1 else "benign",
                    "confidence": round(float(confidence) * 100, 2),
                }
            else:
                pe_feature_result = {
                    "prediction": "unknown",
                    "confidence": 0.0,
                    "reason": "Feature processing failed.",
                }
        else:
            pe_feature_result = {
                "prediction": "unknown",
                "confidence": 0.0,
                "reason": "PE model not loaded or extraction failed.",
            }
        final_result["pe_feature_analysis_result"] = pe_feature_result

        # --- Stage 4.6: 최종 종합 평가 ---
        pe_pred = final_result.get("pe_feature_analysis_result", {}).get("prediction")
        dyn_pred = final_result.get("dynamic_analysis_result", {}).get("prediction")
        vt_ratio = final_result.get("virustotal", {}).get("detection_ratio", "N/A")
        vt_positives = 0
        if " / " in vt_ratio:
            try:
                vt_positives = int(vt_ratio.split(" / ")[0])
            except (ValueError, IndexError):
                vt_positives = 0
        risk_level = "Low"
        risk_desc = "No significant malicious indicators were found."
        if pe_pred == "malware" and dyn_pred == "malware":
            risk_level = "Critical"
            risk_desc = "Both static structure and behavioral patterns are highly indicative of malware."
        elif pe_pred == "malware" or dyn_pred == "malware":
            risk_level = "High"
            risk_desc = (
                "At least one of the AI models detected strong malicious indicators."
            )
        elif vt_positives > 10:
            risk_level = "High"
            risk_desc = "A significant number of antivirus engines on VirusTotal flag this file as malicious."
        elif vt_positives > 2:
            risk_level = "Medium"
            risk_desc = "Several antivirus engines on VirusTotal flag this file, warranting caution."
        elif final_result.get("api_summary", {}).get("suspicious_calls"):
            risk_level = "Suspicious"
            risk_desc = "The file makes suspicious API calls, but does not show definitive malicious behavior."
        final_result["final_assessment"] = {
            "risk_level": risk_level,
            "description": risk_desc,
        }

        # --- Stage 5: DB 저장 ---
        crud.update_task_status(db, "SUCCESS", task_id, result=final_result)
        return final_result

    except (Exception, CalledProcessError) as e:
        error_details = str(e)
        if isinstance(e, CalledProcessError):
            error_details = (
                e.stderr or e.stdout or "Subprocess failed without error message."
            )
        error_result = {
            "error_message": "Analysis pipeline failed.",
            "stage": "AnalysisWorker",
            "details": error_details,
        }
        crud.update_task_status(db, "FAILURE", task_id, result=error_result)
        raise e
    finally:
        db.close()
