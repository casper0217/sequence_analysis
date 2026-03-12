'use client';
import { useCallback, useEffect, useState } from 'react';

// API 주소 함수
const getApiBaseUrl = () => {
  if (typeof window !== 'undefined') return `http://${window.location.hostname}:8000`;
  return 'http://localhost:8000';
};

// --- [UI 컴포넌트 1] 최종 평가 카드 ---
const FinalAssessmentCard = ({ assessment }) => {
  if (!assessment) return null;
  const { risk_level, description } = assessment;
  const riskStyles = {
    "Critical": { color: "#c0392b", icon: "🔴" }, "High": { color: "#e74c3c", icon: "🟠" },
    "Medium": { color: "#f39c12", icon: "🟡" }, "Suspicious": { color: "#f1c40f", icon: "🟡" },
    "Low": { color: "#2ecc71", icon: "🟢" }, "Default": { color: "#34495e", icon: "⚪" },
  };
  const style = riskStyles[risk_level] || riskStyles["Default"];
  return (
    <div style={{ backgroundColor: '#fff', border: `1px solid ${style.color}`, borderRadius: '8px', padding: '1.5rem', boxShadow: '0 5px 15px rgba(0,0,0,0.1)' }}>
      <h3 style={{ marginTop: 0, fontSize: '1.1rem', color: '#495057' }}>{style.icon} Final Assessment</h3>
      <div style={{ textAlign: 'center', padding: '1rem 0' }}>
        <p style={{ margin: 0, fontSize: '2rem', fontWeight: 'bold', color: style.color }}>{risk_level.toUpperCase()}</p>
        <p style={{ margin: '0.5rem 0 0 0', color: '#7f8c8d' }}>{description}</p>
      </div>
    </div>
  );
};

// --- [UI 컴포넌트 2] 모델 예측 결과 카드 ---
const ResultCard = ({ title, result, icon }) => {
  if (!result) return null;
  const { prediction, confidence, reason } = result;
  let color = prediction === 'malware' ? '#e74c3c' : (prediction === 'benign' ? '#2ecc71' : '#7f8c8d');
  const predictionText = prediction ? prediction.charAt(0).toUpperCase() + prediction.slice(1) : 'Unknown';
  return (
    <div style={{ flex: 1, minWidth: '300px', backgroundColor: '#fff', borderLeft: `5px solid ${color}`, borderRadius: '5px', padding: '1.5rem', boxShadow: '0 4px 8px rgba(0,0,0,0.05)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#34495e', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
        <span style={{ fontSize: '1.5rem' }}>{icon}</span><h3 style={{ margin: 0, fontSize: '1.1rem' }}>{title}</h3>
      </div>
      <div>
        <p style={{ margin: '0 0 0.5rem 0', color: '#7f8c8d', fontSize: '0.9rem' }}>Classification Result:</p>
        <p style={{ color: color, fontSize: '1.7rem', fontWeight: 'bold', margin: '0.5rem 0' }}>{predictionText}</p>
        {reason ? <p style={{ color: '#c0392b', fontStyle: 'italic', marginTop: '1rem' }}>Reason: {reason}</p> : (<>
          <p style={{ margin: '1.5rem 0 0.5rem 0', color: '#7f8c8d', fontSize: '0.9rem' }}>Confidence Score:</p>
          <div style={{ width: '100%', backgroundColor: '#ecf0f1', borderRadius: '5px', height: '8px', overflow: 'hidden' }}>
            <div style={{ width: `${confidence || 0}%`, backgroundColor: color, height: '100%', transition: 'width 0.5s ease' }}></div>
          </div>
          <p style={{ textAlign: 'right', margin: '0.5rem 0 0 0', fontWeight: 'bold', color: color }}>{confidence?.toFixed(2) || 0}%</p>
        </>)}
      </div>
    </div>
  );
};

// --- [UI 컴포넌트 3] 파일 기본 정보 카드 ---
const FilePropertiesCard = ({ properties, vtResult }) => {
  const [copyStatus, setCopyStatus] = useState({});
  const copyToClipboard = (text, type) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        setCopyStatus({ [type]: 'Copied!' }); setTimeout(() => setCopyStatus({}), 1500);
      });
    } else {
      const textArea = document.createElement("textarea"); textArea.value = text; textArea.style.position = "absolute"; textArea.style.left = "-9999px";
      document.body.appendChild(textArea); textArea.select();
      try { document.execCommand('copy'); setCopyStatus({ [type]: 'Copied!' }); setTimeout(() => setCopyStatus({}), 1500); }
      finally { document.body.removeChild(textArea); }
    }
  };
  if (!properties) return null;
  return (
    <div style={{ backgroundColor: '#f8f9fa', borderRadius: '8px', padding: '1.5rem', border: '1px solid #dee2e6' }}>
      <h3 style={{ marginTop: 0, fontSize: '1.1rem', color: '#495057' }}>📄 File Properties</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem', alignItems: 'center' }}>
        <div>
          <p style={{ margin: '0.5rem 0', fontSize: '0.9rem' }}><strong>SHA256:</strong></p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input type="text" readOnly value={properties.sha256} style={{ width: '100%', border: '1px solid #ced4da', padding: '0.3rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }} />
            <button onClick={() => copyToClipboard(properties.sha256, 'sha256')} style={{ padding: '0.3rem 0.6rem' }}>{copyStatus.sha256 || 'Copy'}</button>
          </div>
        </div>
        <div>
          <p style={{ margin: '0.5rem 0', fontSize: '0.9rem' }}><strong>MD5:</strong></p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input type="text" readOnly value={properties.md5} style={{ width: '100%', border: '1px solid #ced4da', padding: '0.3rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }} />
            <button onClick={() => copyToClipboard(properties.md5, 'md5')} style={{ padding: '0.3rem 0.6rem' }}>{copyStatus.md5 || 'Copy'}</button>
          </div>
        </div>
        <div><strong>Size:</strong> {properties.size_kb} KB</div>
        <div><strong>Type:</strong> {properties.type?.toUpperCase() || 'UNKNOWN'}</div>
        {vtResult && <div><strong>VirusTotal:</strong><a href={vtResult.link} target="_blank" rel="noopener noreferrer" style={{ marginLeft: '0.5rem', color: vtResult.detection_ratio?.startsWith('0') ? '#2ecc71' : '#e74c3c' }}>{vtResult.detection_ratio}</a></div>}
      </div>
    </div>
  );
};

// ★★★ [신규/UI 컴포넌트 4] DFS 시퀀스(Execution Trace) 시각화 카드 ★★★
// 기존 DetailsCard를 대체하여 AI 모델에 들어가는 시퀀스 형태를 이쁘게 보여줍니다.
const ExecutionTraceCard = ({ sequenceData }) => {
  if (!sequenceData || sequenceData.length === 0) return null;

  return (
    <div style={{ marginTop: '1.5rem', animation: 'fadeIn 0.5s ease-in' }}>
      <h3 style={{ fontSize: '1.2rem', color: '#2c3e50', borderBottom: '2px solid #ecf0f1', paddingBottom: '0.5rem' }}>
        🧬 Execution Flow (DFS Sequence for AI)
      </h3>
      <p style={{ fontSize: '0.85rem', color: '#7f8c8d', marginBottom: '0.5rem' }}>
        The extracted call graph sequence fed into the BigBird model.
      </p>

      {/* 터미널 느낌의 코드 뷰어 */}
      <div style={{
        backgroundColor: '#1e1e1e', borderRadius: '8px', padding: '1rem',
        maxHeight: '400px', overflowY: 'auto', fontFamily: '"Courier New", Courier, monospace',
        fontSize: '0.85rem', color: '#d4d4d4', boxShadow: 'inset 0 2px 5px rgba(0,0,0,0.5)'
      }}>
        {sequenceData.map((item, index) => {
          let color = '#d4d4d4';
          let paddingLeft = '0px';
          let icon = '';
          let text = item;

          // 문자열 패턴에 따라 색상과 들여쓰기(Depth) 표현
          if (item.startsWith('FUNC_START::')) {
            color = '#569cd6'; // 파란색
            icon = '▶ ';
            text = item.replace('FUNC_START::', 'Function: ');
          } else if (item.startsWith('FUNC_END::')) {
            color = '#c586c0'; // 보라색
            icon = '◀ ';
            text = item.replace('FUNC_END::', 'End: ');
          } else if (item.startsWith('API::')) {
            color = '#dcdcaa'; // 노란색
            paddingLeft = '20px'; // API는 함수 내부에 있으므로 들여쓰기
            icon = '⚡ ';
            text = item.replace('API::', '');
          }

          return (
            <div key={index} style={{ color, paddingLeft, marginBottom: '4px', whiteSpace: 'nowrap' }}>
              <span style={{ opacity: 0.5, marginRight: '10px', fontSize: '0.75rem' }}>{(index + 1).toString().padStart(4, '0')}</span>
              {icon}<span style={{ fontWeight: item.startsWith('FUNC_START::') ? 'bold' : 'normal' }}>{text}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};


// ---[수정된 UI 컴포넌트 5] 터미널 스타일 프로그레스 컴포넌트 (ETA 제거) ---
const ProgressIndicator = ({ status, startTime }) => {
  const [elapsedTime, setElapsedTime] = useState(0);

  const PIPELINE_STEPS = [
    { id: 'PENDING', label: 'Waiting in queue...', weight: 2 },
    { id: 'STARTED', label: 'Initializing analysis engine...', weight: 3 },
    { id: 'Analyzing with Ghidra/DotNet...', label: 'Deep Static Analysis (Extracting AST & P-Code)...', weight: 60 },
    { id: 'Preprocessing execution trace...', label: 'Reconstructing Control Flow Graph (DFS)...', weight: 10 },
    { id: 'Extracting file properties...', label: 'Extracting PE/Headers metadata...', weight: 5 },
    { id: 'Querying VirusTotal...', label: 'Checking Threat Intelligence (VirusTotal)...', weight: 5 },
    { id: 'Analyzing PE structure...', label: 'Generating Static AI Features...', weight: 5 },
    { id: 'Generating behavioral sequence...', label: 'Generating Behavioral Sequence (BigBird)...', weight: 5 },
    { id: 'Running AI model inferences...', label: 'Dual AI Model Prediction...', weight: 5 }
  ];

  useEffect(() => {
    if (!startTime) return;
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [startTime]);

  const formatTime = (seconds) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  };

  let currentStepIndex = PIPELINE_STEPS.findIndex(step => status.includes(step.id));
  if (currentStepIndex === -1 && status === 'Uploading...') currentStepIndex = 0;

  let progressPercent = 0;
  let logHistory = [];

  if (currentStepIndex !== -1) {
    for (let i = 0; i < currentStepIndex; i++) {
      progressPercent += PIPELINE_STEPS[i].weight;
      logHistory.push(`[OK] ${PIPELINE_STEPS[i].label}`);
    }
    logHistory.push(`[RUNNING] ${PIPELINE_STEPS[currentStepIndex].label}`);
    // 시각적 덜컥거림을 방지하기 위한 소폭의 애니메이션 가중치
    if (PIPELINE_STEPS[currentStepIndex].weight > 20) {
      const bonus = Math.min(elapsedTime / 4, PIPELINE_STEPS[currentStepIndex].weight - 5);
      progressPercent += bonus;
    }
  }

  return (
    <div style={{ marginTop: '1.5rem', padding: '1.5rem', backgroundColor: '#fff', border: '1px solid #dee2e6', borderRadius: '8px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '0.5rem' }}>
        <div>
          <h3 style={{ margin: 0, color: '#2c3e50', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ display: 'inline-block', width: '14px', height: '14px', border: '2px solid rgba(52,152,219,0.3)', borderRadius: '50%', borderTopColor: '#3498db', animation: 'spin 1s linear infinite' }}></span>
            System Analyzing...
          </h3>
          <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.9rem', color: '#7f8c8d' }}>{status}</p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <p style={{ margin: 0, fontWeight: 'bold', color: '#3498db', fontSize: '1.2rem' }}>{Math.floor(progressPercent)}%</p>
          {/* ETA 제거하고 순수 경과 시간만 표시 */}
          <p style={{ margin: 0, fontSize: '0.85rem', color: '#95a5a6', fontWeight: 'bold' }}>
            Elapsed Time: {formatTime(elapsedTime)}
          </p>
        </div>
      </div>

      <div style={{ width: '100%', backgroundColor: '#ecf0f1', borderRadius: '8px', height: '12px', overflow: 'hidden', marginBottom: '1.5rem' }}>
        <div style={{ width: `${progressPercent}%`, backgroundColor: '#3498db', height: '100%', transition: 'width 1s ease', backgroundImage: 'linear-gradient(45deg, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent)', backgroundSize: '1rem 1rem', animation: 'progress-stripes 1s linear infinite' }}></div>
      </div>

      <div style={{ backgroundColor: '#1e1e1e', borderRadius: '6px', padding: '1rem', color: '#a6e22e', fontFamily: '"Courier New", Courier, monospace', fontSize: '0.85rem', height: '180px', overflowY: 'auto', boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.5)' }}>
        <div style={{ color: '#f8f8f2', marginBottom: '10px' }}>Malware Analysis Engine v2.0 - Active</div>
        {logHistory.map((log, i) => (
          <div key={i} style={{ marginBottom: '4px', color: log.includes('[OK]') ? '#a6e22e' : '#f1c40f' }}>
            {`> ${log}`}
            {i === logHistory.length - 1 && log.includes('[RUNNING]') && (
              <span style={{ animation: 'blink 1s step-end infinite' }}>_</span>
            )}
          </div>
        ))}
      </div>
      <style jsx>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes blink { 50% { opacity: 0; } }
        @keyframes progress-stripes { from { background-position: 1rem 0; } to { background-position: 0 0; } }
      `}</style>
    </div>
  );
};


// --- 메인 페이지 컴포넌트 ---
export default function Home() {
  const [file, setFile] = useState(null);
  const [task, setTask] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [analysisStartTime, setAnalysisStartTime] = useState(null);

  const handleFile = (selectedFile) => {
    if (selectedFile) { setFile(selectedFile); setError(null); }
  };
  const handleFileChange = (e) => handleFile(e.target.files[0]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;
    setIsLoading(true);
    setError(null);
    setAnalysisStartTime(Date.now());
    setTask({ status: 'Uploading...', filename: file.name, result: null });

    const formData = new FormData();
    formData.append('file', file);
    try {
      const API_BASE_URL = getApiBaseUrl();
      const uploadRes = await fetch(`${API_BASE_URL}/upload/`, { method: 'POST', body: formData });
      if (!uploadRes.ok) {
        const errorData = await uploadRes.json().catch(() => ({ detail: 'Upload failed.' }));
        throw new Error(errorData.detail);
      }
      const data = await uploadRes.json();
      setTask(data);
    } catch (err) { setError(`Upload Error: ${err.message}`); setIsLoading(false); }
  };

  const pollTaskStatus = useCallback(async () => {
    if (!task?.id || !isLoading) return;
    try {
      const API_BASE_URL = getApiBaseUrl();
      const resultRes = await fetch(`${API_BASE_URL}/result/${task.id}`);
      if (!resultRes.ok) throw new Error('Polling failed');
      const data = await resultRes.json();
      setTask(data);
    } catch (err) { setError(`Network Error: ${err.message}`); setIsLoading(false); }
  }, [task, isLoading]);

  useEffect(() => {
    if (isLoading) {
      const id = setInterval(pollTaskStatus, 3000);
      return () => clearInterval(id);
    }
  }, [isLoading, pollTaskStatus]);

  useEffect(() => {
    if (task && (task.status.includes('SUCCESS') || task.status.includes('FAILURE'))) {
      setIsLoading(false);
    }
  }, [task]);

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setIsDragging(false); };
  const handleDrop = (e) => {
    e.preventDefault(); setIsDragging(false);
    if (e.dataTransfer.files?.[0]) handleFile(e.dataTransfer.files[0]);
  };

  const getStatusColor = (status) => {
    if (status && status.includes('Cache')) return '#16a085';
    if (status === 'SUCCESS') return '#27ae60';
    if (status === 'FAILURE') return '#c0392b';
    return status ? '#3498db' : '#2c3e50';
  };

  return (
    <main style={{ fontFamily: 'sans-serif', maxWidth: '950px', margin: 'auto', padding: '2rem', backgroundColor: '#f4f7f9', minHeight: '100vh' }}>
      <header style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h1 style={{ color: '#2c3e50', fontSize: '2.5rem', marginBottom: '0.5rem' }}>Malware Analysis Service</h1>
        <p style={{ color: '#7f8c8d', fontSize: '1.1rem' }}>Upload an executable file to analyze its behavior via Deep Static & AI Models.</p>
      </header>

      <section
        style={{ marginBottom: '2rem', padding: '2.5rem', borderRadius: '12px', border: isDragging ? '2px dashed #3498db' : '2px dashed #bdc3c7', backgroundColor: isDragging ? '#eaf5ff' : '#ffffff', textAlign: 'center', transition: 'all 0.3s ease', boxShadow: '0 4px 6px rgba(0,0,0,0.05)' }}
        onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
      >
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', alignItems: 'center' }}>
          <div style={{ fontSize: '3rem', marginBottom: '-1rem' }}>📁</div>
          <p style={{ margin: 0, color: '#34495e', fontSize: '1.1rem' }}>Drag & Drop your PE file here or click to browse</p>
          {file ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', backgroundColor: '#f8f9fa', padding: '0.8rem 1.5rem', borderRadius: '8px', border: '1px solid #dee2e6' }}>
              <span style={{ fontWeight: 'bold', color: '#2c3e50' }}>{file.name}</span>
              <span style={{ color: '#7f8c8d', fontSize: '0.9rem' }}>({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
              <button type="button" onClick={() => setFile(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#e74c3c', fontSize: '1.2rem', padding: '0' }}>✖</button>
            </div>
          ) : (<label style={{ cursor: 'pointer', padding: '0.8rem 1.5rem', border: '2px solid #3498db', borderRadius: '6px', color: '#3498db', backgroundColor: '#fff', fontWeight: 'bold', transition: 'all 0.2s' }}>Select File<input type="file" onChange={handleFileChange} style={{ display: 'none' }} /></label>)}
          <button type="submit" disabled={!file || isLoading} style={{ padding: '1rem 3rem', cursor: !file || isLoading ? 'not-allowed' : 'pointer', backgroundColor: !file || isLoading ? '#bdc3c7' : '#2ecc71', color: 'white', border: 'none', borderRadius: '6px', fontSize: '1.1rem', fontWeight: 'bold', transition: 'background-color 0.2s', boxShadow: '0 4px 6px rgba(46, 204, 113, 0.3)' }}>
            {isLoading ? 'Processing...' : 'Start AI Analysis'}
          </button>
        </form>
      </section>

      {error && <div style={{ backgroundColor: '#fdf0ed', color: '#c0392b', padding: '1rem', borderRadius: '8px', textAlign: 'center', fontWeight: 'bold', border: '1px solid #fadbd8', marginBottom: '2rem' }}>⚠️ {error}</div>}

      {task && (
        <section>
          <div style={{ padding: '1rem', backgroundColor: '#fff', borderRadius: '8px', borderLeft: `5px solid ${getStatusColor(task.status)}`, boxShadow: '0 2px 4px rgba(0,0,0,0.05)', marginBottom: '1.5rem' }}>
            <p style={{ margin: 0, fontSize: '1.1rem' }}>
              <strong>Target:</strong> <span style={{ fontFamily: 'monospace' }}>{task.filename}</span> &nbsp;|&nbsp;
              <strong>Status:</strong> <span style={{ fontWeight: 'bold', color: getStatusColor(task.status) }}>{task.status}</span>
            </p>
          </div>

          {isLoading && <ProgressIndicator status={task.status} startTime={analysisStartTime} />}

          {!isLoading && task.status.includes('SUCCESS') && task.result && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.5s ease-in' }}>
              <FinalAssessmentCard assessment={task.result.final_assessment} />
              <FilePropertiesCard properties={task.result.file_properties} vtResult={task.result.virustotal} />
              <div>
                <h3 style={{ fontSize: '1.2rem', color: '#2c3e50', borderBottom: '2px solid #ecf0f1', paddingBottom: '0.5rem' }}>🤖 Dual AI Model Predictions</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1.5rem', marginTop: '1rem' }}>
                  <ResultCard title="PE Structure Analysis (Static)" result={task.result.pe_feature_analysis_result} icon="🛡️" />
                  <ResultCard title="API Sequence Analysis (Behavioral)" result={task.result.dynamic_analysis_result} icon="⚙️" />
                </div>
              </div>

              {/* 기존 DetailsCard 대신 DFS Sequence 뷰어를 출력합니다 */}
              <ExecutionTraceCard sequenceData={task.result.unified_sequence || task.result.api_summary?.unified_sequence} />
            </div>
          )}

          {!isLoading && task.status === 'FAILURE' && task.result && (
            <div style={{ marginTop: '1.5rem' }}>
              <h3 style={{ color: '#c0392b' }}>Analysis Error Details</h3>
              <pre style={{ backgroundColor: '#1e1e1e', color: '#e74c3c', padding: '1.5rem', borderRadius: '8px', whiteSpace: 'pre-wrap', fontFamily: 'monospace', overflowX: 'auto' }}>
                {JSON.stringify(task.result, null, 2)}
              </pre>
            </div>
          )}
        </section>
      )}
      <style jsx global>{` @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } } `}</style>
    </main>
  );
}