import argparse
import json
import os
import sys
from collections import OrderedDict, defaultdict
from typing import Dict, List, Optional, Set, Tuple


class CallGraphAnalyzer:
    # --- [핵심 수정] __init__ 함수: 비정상적인 주소를 가진 함수를 필터링하는 로직 추가 ---
    def __init__(self, json_path: str):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(
                f"[!] Error: Failed to read or parse JSON file '{json_path}'. Reason: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

        self.file_name = self.data.get("file_name", os.path.basename(json_path))
        self.md5 = self.data.get("md5", "")
        self.file_type = self.data.get("file_type", "unknown")
        self.target = self.data.get("target", "unknown")

        # 비정상적인 주소(예: '0x1000:0000')를 가진 함수를 안전하게 걸러냄
        self.functions = {}
        for f in self.data.get("functions", []):
            addr = f.get("address")
            # 주소 값이 존재하고, 콜론(:)이 포함되지 않아야 함
            if addr and ":" not in addr:
                try:
                    # 16진수 변환이 가능한지 최종 확인
                    int(addr, 16)
                    self.functions[addr] = f
                except (ValueError, TypeError):
                    print(
                        f"[*] Warning: Skipping function with invalid address format: '{addr}' in {self.file_name}"
                    )

        if not self.functions:
            print(
                f"[!] Error: No valid functions found in '{self.file_name}'. Cannot proceed.",
                file=sys.stderr,
            )
            # 빈 결과를 생성하고 종료하지 않기 위해, 빈 functions 리스트로 계속 진행하도록 할 수도 있음.
            # 여기서는 일단 에러로 간주하고 종료.
            sys.exit(1)

        self.call_graph = self._build_call_graph()
        self.visited = set()
        self.execution_trace = []
        self.api_sequence = []
        self.unified_sequence = []

        sample_addr = list(self.functions.keys())[0]
        addr_len = len(sample_addr.replace("0x", ""))
        self.is_64bit = addr_len > 8

        # 재배치를 위한 목표 ImageBase 설정
        self.image_base = 0x140000000 if self.is_64bit else 0x400000
        # 원본 파일의 ImageBase 추론
        self.original_base = self._detect_original_base()

    def _detect_original_base(self) -> int:
        # __init__ 단계에서 이미 유효한 주소만 self.functions에 담겼으므로,
        # 이 함수는 더 이상 에러를 일으키지 않습니다.
        if not self.functions:
            return 0x140000000 if self.is_64bit else 0x400000

        min_addr = min(int(addr, 16) for addr in self.functions.keys())

        if self.is_64bit:
            return 0x180000000 if min_addr >= 0x180000000 else 0x140000000
        else:
            return 0x10000000 if min_addr >= 0x10000000 else 0x400000

    def _build_call_graph(self) -> Dict[str, List[str]]:
        graph = defaultdict(list)
        for func_addr, func_data in self.functions.items():
            # 안전하게 .get() 사용하여 키가 없는 경우에도 대비
            for call in func_data.get("internal_call_sequence", []):
                called_addr = call.get("address")
                # 호출된 주소가 유효하고, self.functions 목록에 존재하는지 확인
                if called_addr and called_addr in self.functions:
                    graph[func_addr].append(called_addr)
        return dict(graph)

    def rebase_address(self, addr: str, new_base: Optional[int] = None) -> str:
        if new_base is None:
            new_base = self.image_base
        try:
            addr_int = int(addr, 16)
            offset = addr_int - self.original_base
            new_addr = new_base + offset
            return f"0x{new_addr:x}"
        except (ValueError, TypeError):
            # 변환 불가능한 주소는 그대로 반환
            return addr

    def find_entry_points(self) -> List[str]:
        entry_patterns = [
            "main",
            "Main",
            "WinMain",
            "wWinMain",
            "DllMain",
            "DllEntryPoint",
            "entry",
            "Entry",
            "_start",
            "start",
            "EntryPoint",
            "Start",
        ]
        entry_points = []
        for func_addr, func_data in self.functions.items():
            func_name = func_data.get("name", "")
            for pattern in entry_patterns:
                # 대소문자 구분 없이 비교
                if pattern.lower() in func_name.lower():
                    if func_addr not in entry_points:
                        entry_points.append(func_addr)

        if not entry_points and self.functions:
            # Entry Point를 찾지 못하면, 가장 낮은 주소의 함수를 시작점으로 간주
            entry_points = [min(self.functions.keys(), key=lambda x: int(x, 16))]

        return sorted(entry_points, key=lambda x: int(x, 16))

    def dfs_traverse(self, start_addr: str, depth: int = 0, max_depth: int = 100):
        if depth > max_depth or start_addr not in self.functions:
            return

        if start_addr in self.visited:
            self.execution_trace.append(
                {
                    "address": self.rebase_address(start_addr),
                    "original_address": start_addr,
                    "name": self.functions[start_addr]["name"],
                    "type": "reference",
                    "depth": depth,
                    "apis": [],
                }
            )
            return

        self.visited.add(start_addr)
        func_data = self.functions[start_addr]
        api_calls = func_data.get("api_call_sequence", [])

        trace_entry = {
            "address": self.rebase_address(start_addr),
            "original_address": start_addr,
            "name": func_data["name"],
            "type": "call",
            "depth": depth,
            "apis": api_calls,
        }
        self.execution_trace.append(trace_entry)

        self.unified_sequence.append(f"FUNC_START::{func_data['name']}")
        for api in api_calls:
            self.unified_sequence.append(f"API::{api}")

        if start_addr in self.call_graph:
            for called_addr in self.call_graph[start_addr]:
                self.dfs_traverse(called_addr, depth + 1, max_depth)

        self.unified_sequence.append(f"FUNC_END::{func_data['name']}")

        for api in api_calls:
            self.api_sequence.append(
                {
                    "function": func_data["name"],
                    "api": api,
                    "order": len(self.api_sequence),
                }
            )

    def analyze(self, max_depth: int = 100) -> Dict:
        entry_points = self.find_entry_points()
        entry_point_names = [
            self.functions[e]["name"] for e in entry_points if e in self.functions
        ]

        binary_type = "exe"
        for name in entry_point_names:
            if "dllmain" in name.lower() or "dllentry" in name.lower():
                binary_type = "dll"
                break
        if self.file_type == "dotnet" and not any(
            "main" in n.lower() for n in entry_point_names
        ):
            binary_type = "dll"

        print(f"[*] Analyzing: {self.file_name} ({self.file_type}, {binary_type})")
        print(f"[*] Found {len(entry_points)} entry point(s): {entry_point_names}")

        for entry in entry_points:
            if entry in self.functions:
                print(
                    f"[*] Starting DFS from {self.functions[entry]['name']} ({entry})"
                )
                self.dfs_traverse(entry, max_depth=max_depth)

        orphan_functions = []
        for func_addr in self.functions:
            if func_addr not in self.visited:
                orphan_functions.append(
                    {
                        "address": self.rebase_address(func_addr),
                        "original_address": func_addr,
                        "name": self.functions[func_addr]["name"],
                        "apis": self.functions[func_addr].get("api_call_sequence", []),
                    }
                )

        unique_apis_set = set()
        for api_info in self.api_sequence:
            unique_apis_set.add(api_info["api"])

        return {
            "file_name": self.file_name,
            "md5": self.md5,
            "file_type": self.file_type,
            "target": self.target,
            "binary_type": binary_type,
            "architecture": "64-bit" if self.is_64bit else "32-bit",
            "image_base": f"0x{self.image_base:x}",
            "original_base": f"0x{self.original_base:x}",
            "entry_points": entry_point_names,
            "execution_trace": self.execution_trace,
            "api_sequence": self.api_sequence,
            "unified_sequence": self.unified_sequence,
            "orphan_functions": orphan_functions,
            "statistics": {
                "total_functions": len(self.functions),
                "visited_functions": len(self.visited),
                "orphan_functions": len(orphan_functions),
                "total_api_calls": len(self.api_sequence),
                "unique_apis": len(unique_apis_set),
            },
        }


def main():
    parser = argparse.ArgumentParser(
        description="DFS-based call graph analyzer for extracted JSON"
    )
    parser.add_argument("json_file", help="Path to the extracted JSON file")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument(
        "-m", "--max-depth", type=int, default=100, help="Maximum DFS depth"
    )
    parser.add_argument("-b", "--base", help="Custom image base (hex)")
    args = parser.parse_args()

    if not os.path.exists(args.json_file):
        print(f"Error: File not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    try:
        analyzer = CallGraphAnalyzer(args.json_file)
        if args.base:
            analyzer.image_base = int(args.base, 16)

        result = analyzer.analyze(max_depth=args.max_depth)

        print(f"\n[*] Analysis Results:")
        print(f"    - Total functions: {result['statistics']['total_functions']}")
        print(f"    - Visited functions: {result['statistics']['visited_functions']}")
        print(f"    - Total API calls: {result['statistics']['total_api_calls']}")

        output_path = args.output or args.json_file.replace(".json", "_dfs.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print(f"\n[*] Results saved to {output_path}")
        print(f"\n[*] First 20 items in unified sequence:")
        for i, item in enumerate(result.get("unified_sequence", [])[:20], 1):
            print(f"    {i}. {item}")

    except SystemExit as e:
        # CallGraphAnalyzer에서 sys.exit(1)로 종료된 경우를 처리
        if e.code != 0:
            print(f"Analysis aborted due to critical error.", file=sys.stderr)
        # 성공적인 종료는 아무것도 하지 않음
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
