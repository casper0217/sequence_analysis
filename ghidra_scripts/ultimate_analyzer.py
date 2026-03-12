# -*- coding: utf-8 -*-
# @category Analysis
# @description Optimized analysis with labeling and proper output naming.

import hashlib
import json
import os
import time
import traceback
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor


class OptimizedCallAnalyzer:
    """
    정확도를 유지하면서 성능을 최적화한 분석기 클래스.
    Decompiler 같은 무거운 객체를 한 번만 초기화하고 재사용합니다.
    """

    def __init__(self):
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.func_manager = currentProgram.getFunctionManager()
        self.listing = currentProgram.getListing()
        self.call_cache = {}

    def analyze_function_calls(self, func):
        """단일 함수의 직접 및 간접 호출을 모두 분석합니다."""
        func_addr_obj = func.getEntryPoint()
        if func_addr_obj in self.call_cache:
            return self.call_cache[func_addr_obj]

        api_calls = []
        internal_calls = []
        seen_apis = set()
        seen_internals = set()

        instructions = self.listing.getInstructions(func.getBody(), True)
        for instr in instructions:
            if instr.getMnemonicString() not in ["CALL", "call", "BL", "BLX", "JAL"]:
                continue

            for ref in instr.getReferencesFrom():
                to_addr = ref.getToAddress()

                if to_addr.isExternalAddress():
                    called_func = self.func_manager.getFunctionAt(to_addr)
                    if called_func:
                        api_name = called_func.getName(True)
                        if api_name not in seen_apis:
                            api_calls.append(api_name)
                            seen_apis.add(api_name)
                else:
                    called_func = self.func_manager.getFunctionAt(to_addr)
                    if called_func:
                        addr_str = "0x" + called_func.getEntryPoint().toString()
                        if addr_str not in seen_internals:
                            internal_calls.append(
                                OrderedDict(
                                    [
                                        ("name", called_func.getName()),
                                        ("address", addr_str),
                                    ]
                                )
                            )
                            seen_internals.add(addr_str)
        try:
            decompile_results = self.decompiler.decompileFunction(
                func, 30, ConsoleTaskMonitor()
            )
            if decompile_results and decompile_results.decompileCompleted():
                high_func = decompile_results.getHighFunction()
                if high_func:
                    for pcode in high_func.getPcodeOps():
                        if pcode.getOpcode() in [PcodeOp.CALLIND, PcodeOp.BRANCHIND]:
                            call_dest_varnode = pcode.getInput(0)
                            def_pcode = call_dest_varnode.getDef()
                            if def_pcode and def_pcode.getOpcode() == PcodeOp.COPY:
                                source_varnode = def_pcode.getInput(0)
                                if source_varnode.isConstant():
                                    dest_addr_offset = source_varnode.getOffset()
                                    dest_addr = func.getEntryPoint().getNewAddress(
                                        dest_addr_offset
                                    )
                                    called_func = self.func_manager.getFunctionAt(
                                        dest_addr
                                    )
                                    if called_func:
                                        if called_func.isExternal():
                                            api_name = called_func.getName(True)
                                            if api_name not in seen_apis:
                                                api_calls.append(api_name)
                                                seen_apis.add(api_name)
                                        else:
                                            addr_str = (
                                                "0x"
                                                + called_func.getEntryPoint().toString()
                                            )
                                            if addr_str not in seen_internals:
                                                internal_calls.append(
                                                    OrderedDict(
                                                        [
                                                            (
                                                                "name",
                                                                called_func.getName(),
                                                            ),
                                                            ("address", addr_str),
                                                        ]
                                                    )
                                                )
                                                seen_internals.add(addr_str)
        except Exception as e:
            print(
                "[Analyzer] Decopiler error in function '{}' at address {}: {}".format(
                    func.getName(), func.getEntryPoint().toString(), str(e)
                )
            )
            pass

        self.call_cache[func_addr_obj] = (api_calls, internal_calls)
        return api_calls, internal_calls

    def close(self):
        self.decompiler.dispose()


def analyze_all_functions():
    """모든 함수를 분석하고 결과를 반환하는 메인 루프"""
    analyzer = OptimizedCallAnalyzer()
    functions_data = []
    try:
        functions = list(currentProgram.getFunctionManager().getFunctions(True))
        total_funcs = len(functions)
        print("[Analyzer] Found {} functions to analyze.".format(total_funcs))

        for i, func in enumerate(functions):
            if func.isExternal():
                continue

            api_calls, internal_calls = analyzer.analyze_function_calls(func)

            func_name = func.getName()
            if func.isThunk():
                thunked = func.getThunkedFunction(True)
                if thunked and thunked.isExternal():
                    thunk_api = thunked.getName(True)
                    if thunk_api not in api_calls:
                        api_calls.append(thunk_api)
                func_name = "{}_THUNK".format(func_name)

            func_entry = OrderedDict(
                [
                    ("name", func_name),
                    ("address", "0x" + func.getEntryPoint().toString()),
                    ("api_call_sequence", api_calls),
                    ("internal_call_sequence", internal_calls),
                ]
            )
            functions_data.append(func_entry)

            if (i + 1) % 200 == 0:
                print(
                    "[Analyzer] Progress: {}/{} functions analyzed.".format(
                        i + 1, total_funcs
                    )
                )
    finally:
        analyzer.close()

    print("[Analyzer] Analysis of all functions complete.")
    return functions_data


def calc_md5(path):
    """MD5 해시 계산"""
    try:
        md5_hash = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except:
        return ""


# === 메인 실행 로직 ===
if __name__ == "__main__":
    start_time = time.time()
    file_name_with_ext = currentProgram.getName()
    file_path = currentProgram.getExecutablePath()

    script_args = getScriptArgs()
    output_dir = script_args[0] if len(script_args) > 0 else "/tmp"
    label_str = script_args[1] if len(script_args) > 1 else "unknown"

    output_data = OrderedDict(
        [
            ("file_name", file_name_with_ext),
            ("md5", calc_md5(file_path)),
            ("analysis_status", ""),
            ("error", ""),
            ("file_type", "native"),
            ("target", label_str),
            ("functions", []),
            ("analysis_time_seconds", 0.0),
        ]
    )

    try:
        print(
            "[Analyzer] Starting: {} (Label: {})".format(file_name_with_ext, label_str)
        )

        if currentProgram.getFunctionManager().getFunctionCount() < 15:
            analyzeAll(currentProgram)

        output_data["functions"] = analyze_all_functions()

        if not output_data["functions"]:
            output_data["analysis_status"] = "failed_likely_packed_or_obfuscated"
        else:
            total_apis = sum(
                len(f["api_call_sequence"]) for f in output_data["functions"]
            )
            output_data["analysis_status"] = (
                "success" if total_apis > 0 else "success_no_apis"
            )

    except Exception as e:
        error_msg = str(e).split("\n")[0]
        output_data["analysis_status"] = "failed"
        output_data["error"] = error_msg
        print("[Analyzer] CRITICAL ERROR: {}".format(error_msg))
        traceback.print_exc()

    finally:
        duration = time.time() - start_time
        output_data["analysis_time_seconds"] = round(duration, 2)

        # [수정] 파일 이름에서 확장자를 제거하여 JSON 파일 이름 생성
        base_name, _ = os.path.splitext(file_name_with_ext)
        out_path = os.path.join(output_dir, base_name + "_analysis.json")

        with open(out_path, "w") as f:
            json.dump(output_data, f, indent=2)

        status = output_data["analysis_status"]
        func_count = len(output_data["functions"])
        total_calls = sum(len(f["api_call_sequence"]) for f in output_data["functions"])

        log_msg = (
            "[{}] {} | Status: {} | Time: {:.2f}s | Funcs: {} | Calls: {}\n".format(
                "OK" if status.startswith("success") else "FAIL",
                file_name_with_ext,
                status,
                duration,
                func_count,
                total_calls,
            )
        )
        try:
            with open("/home/jy/ghidra/logs/master_analysis_log.txt", "a") as log_f:
                log_f.write(log_msg)
        except:
            pass

        print(
            "[Analyzer] Complete: {} ({:.2f}s). Report saved to {}".format(
                file_name_with_ext, duration, out_path
            )
        )
