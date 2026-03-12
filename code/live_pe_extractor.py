import json
import math
import os
import sys
from collections import Counter

import numpy as np
import pefile
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# analyze_file 함수와 그 헬퍼 함수들을 학습 스크립트에서 그대로 가져옵니다.
# --------------------------------------------------------------------------
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    counts = Counter(data)
    data_len = len(data)
    for count in counts.values():
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)
    return entropy


def analyze_file(file_path):
    # 학습 스크립트의 analyze_file 함수와 거의 동일하지만,
    # target_value 인자를 제거하고 반환값을 약간 수정합니다.
    try:
        pe = pefile.PE(file_path, fast_load=True)

        if not hasattr(pe, "FILE_HEADER") or not hasattr(pe, "OPTIONAL_HEADER"):
            return None

        features = {}  # file_name, target은 제외

        # 그룹 1: 일반 및 헤더 정보
        features["Machine"] = pe.FILE_HEADER.Machine
        features["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        features["TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
        features["Characteristics"] = pe.FILE_HEADER.Characteristics
        features["SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
        features["SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features["SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        features["SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
        features["SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        features["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        features["SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features["SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve

        # 그룹 2: 섹션 정보
        sections = pe.sections
        features["num_sections"] = len(sections)
        if sections:
            section_entropies = [s.get_entropy() for s in sections]
            section_sizes = [s.SizeOfRawData for s in sections]
            features["section_entropy_mean"] = float(np.mean(section_entropies))
            features["section_entropy_std"] = float(np.std(section_entropies))
            features["section_size_mean"] = float(np.mean(section_sizes))
            features["section_size_std"] = float(np.std(section_sizes))
            executable_sections = [
                s for s in sections if s.Characteristics & 0x20000000
            ]
            features["num_executable_sections"] = len(executable_sections)
            features["executable_entropy_mean"] = (
                float(np.mean([s.get_entropy() for s in executable_sections]))
                if executable_sections
                else 0.0
            )
            features["num_wx_sections"] = sum(
                1
                for s in sections
                if s.Characteristics & 0x80000000 and s.Characteristics & 0x20000000
            )
        else:
            (
                features["section_entropy_mean"],
                features["section_entropy_std"],
                features["section_size_mean"],
                features["section_size_std"],
                features["num_executable_sections"],
                features["executable_entropy_mean"],
                features["num_wx_sections"],
            ) = (0.0, 0.0, 0.0, 0.0, 0, 0.0, 0)

        # 그룹 3: 임포트 및 익스포트 정보
        features["num_imports"], features["num_imported_libs"] = (0, 0)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            features["num_imported_libs"] = len(pe.DIRECTORY_ENTRY_IMPORT)
            features["num_imports"] = sum(
                len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT
            )
        features["num_exports"] = (
            len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
            else 0
        )

        # 그룹 4: 인증서 심층 분석
        (
            features["is_signed"],
            features["is_self_signed"],
            features["signature_valid"],
        ) = 0, 0, 0
        features["cert_validity_days"] = -1
        features["issuer_is_suspicious"], features["subject_is_suspicious"] = 0, 0

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if sec_dir.VirtualAddress > 0:
            features["is_signed"] = 1
            try:
                pkcs7_data = pe.write()[sec_dir.VirtualAddress + 8 :]
                content_info = cms.ContentInfo.load(pkcs7_data)
                signed_data = content_info["content"]
                cert_data = signed_data["certificates"][0].chosen.dump()
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                start_date = cert.not_valid_before
                end_date = cert.not_valid_after
                features["cert_validity_days"] = (end_date - start_date).days
                if cert.issuer == cert.subject:
                    features["is_self_signed"] = 1
                issuer_str = cert.issuer.rfc4514_string().lower()
                subject_str = cert.subject.rfc4514_string().lower()
                suspicious_keywords = ["test", "self-signed", "example"]
                if any(keyword in issuer_str for keyword in suspicious_keywords):
                    features["issuer_is_suspicious"] = 1
                if any(keyword in subject_str for keyword in suspicious_keywords):
                    features["subject_is_suspicious"] = 1
                features["signature_valid"] = 1
            except Exception:
                features["signature_valid"] = 0

        # JSON 직렬화를 위해 numpy 타입을 파이썬 기본 타입으로 변환
        for key, value in features.items():
            if isinstance(value, (np.integer, np.int64)):
                features[key] = int(value)
            elif isinstance(value, (np.floating, np.float64)):
                features[key] = float(value)
        return features
    except Exception:
        return None


# --------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 live_pe_extractor.py <file_path>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    extracted_features = analyze_file(file_path)

    if extracted_features:
        print(json.dumps(extracted_features, indent=2))
    else:
        # 분석 실패 시 빈 JSON 객체 출력
        print(json.dumps({}))
