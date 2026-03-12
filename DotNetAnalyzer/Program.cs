using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

public class FunctionRef
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";
    [JsonPropertyName("address")]
    public string Address { get; set; } = "";
}

public class FunctionInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";
    [JsonPropertyName("address")]
    public string Address { get; set; } = "";
    [JsonPropertyName("api_call_sequence")]
    public List<string> ApiCallSequence { get; set; } = new();
    [JsonPropertyName("internal_call_sequence")]
    public List<FunctionRef> InternalCallSequence { get; set; } = new();
}

public class AnalysisResult
{
    [JsonPropertyName("file_name")]
    public string FileName { get; set; } = "";
    [JsonPropertyName("md5")]
    public string MD5 { get; set; } = "";
    [JsonPropertyName("analysis_status")]
    public string AnalysisStatus { get; set; } = "";
    [JsonPropertyName("error")]
    public string Error { get; set; } = "";
    [JsonPropertyName("file_type")]
    public string FileType { get; set; } = "dotnet";
    [JsonPropertyName("target")]
    public string Target { get; set; } = "unknown";
    [JsonPropertyName("functions")]
    public List<FunctionInfo> Functions { get; set; } = new();
    [JsonPropertyName("analysis_time_seconds")]
    public double AnalysisTimeSeconds { get; set; } = 0.0;
}

namespace DotNetAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.Error.WriteLine("Usage: DotNetAnalyzer <input_file_path> <output_json_path> <label>");
                Environment.Exit(1);
            }

            string inputFile = args[0];
            string outputJson = args[1];
            string label = args[2];

            var stopwatch = Stopwatch.StartNew();
            var result = new AnalysisResult
            {
                FileName = Path.GetFileName(inputFile),
                MD5 = CalculateMD5(inputFile),
                Target = label
            };

            try
            {
                Console.WriteLine($"[DotNetAnalyzer] Starting: {result.FileName} (Label: {label})");
                AnalyzeFileInParallel(inputFile, result);
                result.AnalysisStatus = result.Functions.Any() ? "success" : "success_no_apis";
            }
            catch (Exception ex)
            {
                result.AnalysisStatus = "failed";
                result.Error = ex.Message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "Unknown error";
                Console.Error.WriteLine($"[DotNetAnalyzer] CRITICAL ERROR: {result.Error}");
            }

            stopwatch.Stop();
            result.AnalysisTimeSeconds = Math.Round(stopwatch.Elapsed.TotalSeconds, 2);

            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                File.WriteAllText(outputJson, JsonSerializer.Serialize(result, options));

                // 마스터 로그 기록 (경로는 환경에 맞게 조정하세요)
                string logPath = "/home/jy/ghidra/logs/master_analysis_log.txt";
                string status = result.AnalysisStatus.StartsWith("success") ? "OK" : "FAIL";
                string logMessage = $"[{status}] {result.FileName,-60} | Status: {result.AnalysisStatus,-20} | Time: {result.AnalysisTimeSeconds:F2}s | Funcs: {result.Functions.Count}\n";

                Directory.CreateDirectory(Path.GetDirectoryName(logPath));
                File.AppendAllText(logPath, logMessage);

                Console.WriteLine($"[DotNetAnalyzer] Done: {result.FileName} ({result.AnalysisTimeSeconds:F2}s, {result.Functions.Count} functions)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[DotNetAnalyzer] Failed to save results: {ex.Message}");
                Environment.Exit(1);
            }
        }

        static void AnalyzeFileInParallel(string filePath, AnalysisResult result)
        {
            ModuleDefMD module = null;
            try
            {
                module = ModuleDefMD.Load(filePath);
                var functions = new ConcurrentBag<FunctionInfo>();

                // 몸체가 있는 모든 메서드 추출
                var allMethods = module.GetTypes()
                    .SelectMany(type => type.Methods.Where(m => m.HasBody)
                    .Select(method => (type, method))).ToList();

                Parallel.ForEach(allMethods, methodTuple =>
                {
                    var (type, method) = methodTuple;
                    var functionInfo = AnalyzeSingleMethod(type, method, module);
                    if (functionInfo != null)
                    {
                        functions.Add(functionInfo);
                    }
                });

                // 주소(MDToken) 순으로 정렬하여 리스트에 담기
                result.Functions = functions.OrderBy(f => Convert.ToUInt32(f.Address.Replace("0x", ""), 16)).ToList();
            }
            catch (BadImageFormatException ex)
            {
                result.AnalysisStatus = "failed_likely_packed_or_obfuscated";
                result.Error = $"BadImageFormatException: {ex.Message}";
            }
            finally
            {
                module?.Dispose();
            }
        }

        static FunctionInfo AnalyzeSingleMethod(TypeDef type, MethodDef method, ModuleDef currentModule)
        {
            var functionInfo = new FunctionInfo
            {
                Name = $"{type.FullName}::{method.Name}",
                Address = $"0x{method.MDToken.Raw:X8}"
            };

            var seenApis = new HashSet<string>();
            var seenInternals = new HashSet<string>();

            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt || instruction.OpCode == OpCodes.Newobj)
                {
                    if (instruction.Operand is IMethod calledMethod)
                    {
                        // 1. P/Invoke (Native API) 체크
                        if (calledMethod is MethodDef calledMethodDef && calledMethodDef.IsPinvokeImpl)
                        {
                            var implMap = calledMethodDef.ImplMap;
                            if (implMap != null && implMap.Module != null)
                            {
                                string pinvokeSignature = $"[PInvoke] {implMap.Module.Name}::{implMap.Name}";
                                if (seenApis.Add(pinvokeSignature))
                                {
                                    functionInfo.ApiCallSequence.Add(pinvokeSignature);
                                }
                                continue;
                            }
                        }

                        // 2. 일반 외부 API vs 내부 함수 구분
                        if (IsExternalApi(calledMethod, currentModule))
                        {
                            string methodSignature = FormatMethodSignature(calledMethod);
                            if (seenApis.Add(methodSignature))
                            {
                                functionInfo.ApiCallSequence.Add(methodSignature);
                            }
                        }
                        else
                        {
                            string address = $"0x{calledMethod.MDToken.Raw:X8}";
                            if (seenInternals.Add(address))
                            {
                                functionInfo.InternalCallSequence.Add(new FunctionRef
                                {
                                    Name = FormatMethodSignature(calledMethod),
                                    Address = address
                                });
                            }
                        }
                    }
                }
            }

            return (functionInfo.ApiCallSequence.Count > 0 || functionInfo.InternalCallSequence.Count > 0) ? functionInfo : null;
        }

        static bool IsExternalApi(IMethod method, ModuleDef currentModule)
        {
            // 선언된 모듈이 현재 분석 중인 모듈과 다르면 외부 API로 간주
            return method.DeclaringType?.Module != currentModule;
        }

        static string FormatMethodSignature(IMethod method)
        {
            if (method == null) return "UnknownMethod";
            var typeName = method.DeclaringType?.FullName ?? "UnknownType";
            return $"{typeName}::{method.Name}";
        }

        static string CalculateMD5(string filePath)
        {
            try
            {
                using var md5 = MD5.Create();
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch { return ""; }
        }
    }
}