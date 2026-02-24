"use client";

import { useState, useRef, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader, TechLoader } from "@/components/ui/loader";
import { Markdown } from "@/components/ui/markdown";
import { Button } from "@/components/ui/button";
import { Sidebar } from "@/components/layout/sidebar";
import {
  Globe,
  Check,
  AlertCircle,
  Activity,
  Info,
  AlertTriangle,
  Sparkles,
  Download,
  Eye,
  Terminal,
  ChevronDown,
  Shield,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

// ─────────────────────────────────────────────────────────────────
//  HACKER'S EYE VIEW COMPONENT
// ─────────────────────────────────────────────────────────────────

function HackerEyeView({ findings, targetUrl, onExit }) {
  const [revealedLines, setRevealedLines] = useState(0);
  const [displayedText, setDisplayedText] = useState("");
  const [showMeter, setShowMeter] = useState(false);
  const [cursorVisible, setCursorVisible] = useState(true);

  const attackerLines = findings.map((f, i) => {
    const severity = f.severity || "Low";
    const type = f.v_type || f.title || "Unknown vector";
    const evidence = f.evidence || f.description || "";
    const risk = f.risk_score || 0;
    const addr = (0x7fff0000 + i * 0x1a2).toString(16).toUpperCase();

    if (severity === "High") {
      return {
        prefix: "CRITICAL",
        color: "#ff3333",
        glow: "rgba(255,51,51,0.5)",
        line: `[ADDR:0x${addr}] ${type} ALERT: UNPROTECTED VECTOR DETECTED AT ${f.affected_url || targetUrl}. PROOF: ${evidence.slice(0, 50)}...`,
        icon: "💀",
      };
    } else if (severity === "Medium") {
      return {
        prefix: "HIGH-VAL",
        color: "#ff9900",
        glow: "rgba(255,153,0,0.4)",
        line: `[ADDR:0x${addr}] ${type} VULNERABILITY MAPPED ON ${f.affected_url || targetUrl}. RISK_INDEX: ${risk}/100.`,
        icon: "⚡",
      };
    } else {
      return {
        prefix: "SURFACE ",
        color: "#00ff66",
        glow: "rgba(0,255,102,0.3)",
        line: `[ADDR:0x${addr}] ${type} EXPOSURE AT ${f.affected_url || targetUrl}. LATERAL MOVEMENT POSSIBLE.`,
        icon: "🔭",
      };
    }
  });

  const systemLines = [
    { prefix: "BRIDGE  ", color: "#64748b", line: "Establishing neural link to " + targetUrl + "...", icon: "◈" },
    { prefix: "PROBE   ", color: "#64748b", line: "Injecting reconnaissance payloads into stack... Done.", icon: "◈" },
    { prefix: "TRIAGE  ", color: "#64748b", line: `${findings.length} points of interest identified. Decrypting findings...`, icon: "◈" },
    { prefix: "------", color: "#1e293b", line: "━".repeat(60), icon: "" },
  ];

  const allLines = [...systemLines, ...attackerLines];

  // Typewriter effect logic
  useEffect(() => {
    if (revealedLines >= allLines.length) {
      setTimeout(() => setShowMeter(true), 600);
      return;
    }

    let charIdx = 0;
    const currentLine = allLines[revealedLines].line;
    setDisplayedText("");

    const typeInterval = setInterval(() => {
      if (charIdx < currentLine.length) {
        setDisplayedText((prev) => prev + currentLine[charIdx]);
        charIdx++;
      } else {
        clearInterval(typeInterval);
        setTimeout(() => {
          setRevealedLines((prev) => prev + 1);
        }, 300);
      }
    }, 15);

    return () => clearInterval(typeInterval);
  }, [revealedLines, allLines.length]);

  useEffect(() => {
    const interval = setInterval(() => setCursorVisible((v) => !v), 400);
    return () => clearInterval(interval);
  }, []);

  const highCount = findings.filter((f) => f.severity === "High").length;
  const mediumCount = findings.filter((f) => f.severity === "Medium").length;
  const avgRisk = findings.length > 0 ? Math.round(findings.reduce((s, f) => s + (f.risk_score || 50), 0) / findings.length) : 0;

  let timeToBreach = "~2 hours";
  let skillRequired = "ELITE";
  let urgencyColor = "#00ff66";
  let urgencyGlow = "rgba(0,255,102,0.5)";

  if (highCount >= 1) {
    timeToBreach = highCount >= 3 ? "~5 minutes" : "~15 minutes";
    skillRequired = "SKID-LEVEL";
    urgencyColor = "#ff3333";
    urgencyGlow = "rgba(255,51,51,0.5)";
  } else if (mediumCount >= 2) {
    timeToBreach = "~45 minutes";
    skillRequired = "INTERMEDIATE";
    urgencyColor = "#ff9900";
    urgencyGlow = "rgba(255,153,0,0.5)";
  }

  return (
    <div className="fixed inset-0 z-[9999] bg-[#02040a] font-mono overflow-y-auto animate-in fade-in duration-700 selection:bg-[#00ff66] selection:text-black">
      {/* Visual Effects Layers */}
      <div className="fixed inset-0 pointer-events-none z-10 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] animate-pulse" />
      <div className="fixed inset-0 pointer-events-none z-10 bg-[radial-gradient(ellipse_at_center,transparent_0%,rgba(0,0,0,0.4)_100%)]" />
      <div className="fixed inset-0 pointer-events-none z-10 border-[30px] border-black opacity-40 shadow-[inset_0_0_100px_rgba(0,0,0,1)]" />

      <div className="relative z-20 max-w-[900px] mx-auto px-8 py-16 pb-32">
        {/* Header Section */}
        <div className="mb-12 relative">
          <div className="absolute -top-4 -left-4 w-8 h-8 border-t-2 border-l-2 border-[#1e293b]" />
          <div className="absolute -top-4 -right-4 w-8 h-8 border-t-2 border-r-2 border-[#1e293b]" />
          
          <div className="flex flex-col gap-1 pl-2">
            <div className="flex items-center gap-3">
              <span className="flex h-2 w-2 rounded-full bg-red-500 animate-ping" />
              <span className="text-[#ff3333] text-[10px] font-black tracking-[0.4em] uppercase">
                NODE_BREACH_SIMULATION // CLASSIFIED_INTEL
              </span>
            </div>
            
            <h1 className="text-4xl font-extrabold text-[#00ff66] tracking-tighter mt-2 flex items-center gap-4">
              <span className="opacity-40 font-light select-none">/</span>
              ARHMORA_EYE_v2.0
              <span className="bg-[#00ff66]/10 text-[#00ff66] text-xs py-1 px-3 rounded-md border border-[#00ff66]/20 font-bold ml-2">ATTACK_STANCE</span>
            </h1>
            
            <div className="mt-4 flex items-center gap-6 text-[10px] text-[#475569] font-bold tracking-widest uppercase">
              <div className="flex items-center gap-2">
                <span className="text-[#64748b]">TAR:</span>
                <span className="text-[#94a3b8]">{targetUrl}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#64748b]">INF:</span>
                <span className="text-[#94a3b8]">8.4 Gbit/s</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#64748b]">STA:</span>
                <span className="text-[#00ff66] animate-pulse">OVERRIDE_ENABLED</span>
              </div>
            </div>
          </div>
        </div>

        {/* Terminal Text Feed */}
        <div className="flex flex-col gap-2 min-h-[400px]">
          {allLines.slice(0, revealedLines).map((line, idx) => (
            <div key={idx} className="flex items-start gap-5 py-0.5 group">
              <span className="text-[#475569] text-xs pt-1 font-bold min-w-[20px] group-hover:text-[#64748b] transition-colors">{line.icon}</span>
              <div className="flex-1 flex flex-col md:flex-row md:items-center gap-2 md:gap-5">
                <span className={cn(
                  "text-[10px] font-black tracking-widest px-2 py-0.5 rounded-sm shrink-0 w-fit",
                  line.prefix === "CRITICAL" ? "bg-red-500/10 text-red-500 border border-red-500/20" :
                  line.prefix === "HIGH-VAL" ? "bg-amber-500/10 text-amber-500 border border-amber-500/20" :
                  "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                )} style={{ textShadow: `0 0 10px ${line.glow}` }}>
                  {line.prefix}
                </span>
                <span className="text-[13px] font-medium leading-relaxed tracking-tight" style={{ 
                  color: idx < systemLines.length ? "#64748b" : "#e2e8f0",
                  textShadow: idx >= systemLines.length ? `0 0 4px rgba(226,232,240,0.3)` : "none"
                }}>
                  {line.line}
                </span>
              </div>
            </div>
          ))}

          {revealedLines < allLines.length && (
            <div className="flex items-start gap-5 py-0.5">
              <span className="text-[#00ff66] text-xs pt-1">▸</span>
              <div className="flex-1 flex flex-col md:flex-row md:items-center gap-2 md:gap-5">
                 <span className={cn(
                  "text-[10px] font-black tracking-widest px-2 py-0.5 rounded-sm shrink-0 w-fit",
                  allLines[revealedLines].prefix === "CRITICAL" ? "bg-red-500/10 text-red-500 border border-red-500/20" :
                  allLines[revealedLines].prefix === "HIGH-VAL" ? "bg-amber-500/10 text-amber-500 border border-amber-500/20" :
                  "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                )}>
                  {allLines[revealedLines].prefix}
                </span>
                <span className="text-[13px] font-medium leading-relaxed tracking-tight text-[#e2e8f0]">
                  {displayedText}
                  <span className={cn("ml-1 inline-block w-2.5 h-4 bg-[#00ff66] align-middle", cursorVisible ? "opacity-100" : "opacity-0")}></span>
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Threat Level Overlay HUD */}
        {showMeter && (
          <div className="mt-16 animate-in slide-in-from-bottom-8 fade-in duration-1000">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 p-10 bg-black/40 border-t-2 border-b-2 border-white/5 backdrop-blur-sm relative overflow-hidden group">
              <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#00ff66]/30 to-transparent animate-shimmer" />
              
              <div className="flex flex-col gap-6 relative z-10">
                 <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-black text-[#475569] uppercase tracking-[0.3em]">Breach Complexity</span>
                    <span className="text-4xl font-black tracking-tighter" style={{ color: urgencyColor, textShadow: `0 0 15px ${urgencyGlow}` }}>{skillRequired}</span>
                 </div>
                 <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-black text-[#475569] uppercase tracking-[0.3em]">Estimated TTL</span>
                    <span className="text-4xl font-black text-white tracking-tighter">{timeToBreach}</span>
                 </div>
              </div>

              <div className="flex flex-col justify-center items-center gap-4 py-4 md:border-x border-white/5 relative z-10">
                 <div className="p-6 rounded-full border-4 border-dashed border-[#1e293b] flex items-center justify-center relative animate-[spin_20s_linear_infinite]">
                    <div className="absolute inset-0 rounded-full bg-gradient-to-tr from-[#00ff66]/10 to-transparent opacity-50" />
                 </div>
                 <div className="absolute flex flex-col items-center">
                    <span className="text-[11px] font-black text-[#475569] uppercase tracking-widest mb-1">Risk</span>
                    <span className="text-5xl font-extrabold text-white tracking-tighter">{avgRisk}</span>
                 </div>
                 <div className="text-[11px] font-black text-[#475569] uppercase tracking-[0.3em]">Composite Intelligence</div>
              </div>

              <div className="flex flex-col gap-6 items-end text-right relative z-10">
                 <div className="flex flex-col gap-2 w-full">
                    <div className="flex justify-between items-center text-[12px] font-black uppercase tracking-widest mb-1">
                       <span className="text-[#475569]">System Integrity</span>
                       <span style={{ color: urgencyColor }}>{100 - avgRisk}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-[#1e293b] rounded-full overflow-hidden p-[2px]">
                       <div className="h-full rounded-full transition-all duration-1000 ease-out shadow-[0_0_15px_currentColor]" style={{ width: `${100 - avgRisk}%`, backgroundColor: urgencyColor }} />
                    </div>
                 </div>
                 <div className="text-[12px] text-[#475569] font-bold leading-relaxed uppercase tracking-tighter">
                   {highCount > 0
                    ? `CRITICAL EXPLOITS DETECTED. SYSTEM COMPROMISE IS INEVITABLE WITHOUT PATCHING.`
                    : `LOW-MEDIUM VECTORS DETECTED. MONITORING REQUIRED.`}
                 </div>
              </div>
            </div>

            <div className="mt-16 flex flex-col items-center gap-4">
              <button
                onClick={onExit}
                className="group relative flex items-center gap-4 px-12 py-5 bg-[#00ff66] text-black rounded-sm text-xs font-black tracking-[0.4em] uppercase hover:bg-white transition-all active:scale-[0.98] shadow-[0_0_50px_rgba(0,255,102,0.3)]"
              >
                RETURN_TO_CONTROL_PLATFORM
                <div className="absolute inset-x-0 -bottom-1 h-[2px] bg-black/20" />
              </button>
              <span className="text-[9px] text-[#475569] font-bold tracking-widest opacity-50">END_OF_TRANSMISSION // 0xCC741</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
//  FINDING CARD
// ─────────────────────────────────────────────────────────────────

function FindingListItem({ msg }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [viewMode, setViewMode] = useState("simple");

  const severityColor = msg.severity === "High" ? "text-red-600 dark:text-red-500" : 
                        msg.severity === "Medium" ? "text-amber-600 dark:text-amber-500" : "text-[#1153ed] dark:text-blue-400";
  const severityBg = msg.severity === "High" ? "bg-red-500" : 
                     msg.severity === "Medium" ? "bg-amber-500" : "bg-[#1153ed]";

  return (
    <div className={cn(
      "w-full bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[24px] overflow-hidden transition-all duration-300",
      isExpanded ? "shadow-2xl ring-1 ring-[#1153ed]/10" : "hover:border-[#1153ed]/20"
    )}>
      {/* Header Area */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        className="p-8 flex items-start justify-between cursor-pointer group"
      >
        <div className="flex items-start gap-6">
          <div className={cn("w-2 h-14 rounded-full shrink-0", severityBg)} />
          <div className="flex flex-col">
            <span className={cn("text-[10px] font-black uppercase tracking-[0.2em] mb-1 opacity-70", severityColor)}>
              {msg.severity} Severity
            </span>
            <h3 className="text-2xl font-bold text-[#1153ed] dark:text-blue-400 tracking-tight group-hover:opacity-80 transition-opacity">
              {msg.ai_classification || msg.v_type || msg.title || "Unknown Vulnerability"}
            </h3>
          </div>
        </div>

        <div className="flex items-center gap-12">
          {/* Metrics Panel */}
          <div className="flex items-center gap-10">
            <div className="text-center">
              <p className="text-[9px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest mb-1.5 opacity-50">Risk</p>
              <p className={cn(
                "text-2xl font-bold font-mono tracking-tighter",
                msg.risk_score > 75 ? "text-red-600" : "text-[#131415] dark:text-white"
              )}>{msg.risk_score}</p>
            </div>
            <div className="text-center">
              <p className="text-[9px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest mb-1.5 opacity-50">Conf.</p>
              <p className="text-2xl font-bold text-[#131415] dark:text-white font-mono tracking-tighter">
                {msg.ai_confidence ? (msg.ai_confidence * 100).toFixed(0) : (msg.pattern_confidence || 85)}%
              </p>
            </div>
            <div className="text-center">
              <p className="text-[9px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest mb-1.5 opacity-50">Status</p>
              <span className="bg-[#f2f4f7] dark:bg-[#1e293b] text-[#767a8c] dark:text-[#94a3b8] text-[10px] font-bold px-3 py-1 rounded-full border border-[#eaecf0] dark:border-[#2a2b2c]">
                {msg.validation_status === 'validated' ? 'Validated' : 'Pending'}
              </span>
            </div>
          </div>

          <button className={cn(
            "w-10 h-10 rounded-full flex items-center justify-center transition-all shadow-lg shadow-blue-500/10",
            isExpanded ? "bg-[#1153ed] text-white" : "bg-[#f2f4f7] dark:bg-[#1e293b] text-[#1153ed] dark:text-blue-400 hover:bg-white dark:hover:bg-slate-800 border border-[#eaecf0] dark:border-[#2a2b2c]"
          )}>
            <ChevronDown className={cn("w-5 h-5 transition-transform duration-300", isExpanded && "rotate-180")} />
          </button>
        </div>
      </div>

      {/* Expanded Content Area */}
      {isExpanded && (
        <div className="p-8 pt-0 border-t border-[#f8fafc] dark:border-[#2a2b2c] animate-in slide-in-from-top-2 duration-300">
          <div className="flex flex-col gap-10 pt-8 max-w-4xl">
            {/* Row 1: Technical Evidence & Location */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="flex flex-col gap-5">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] border border-[#eaecf0] dark:border-[#2a2b2c]">
                    <Globe size={18} />
                  </div>
                  <h4 className="text-[11px] font-black uppercase tracking-widest text-[#131415] dark:text-white">Vulnerability Location</h4>
                </div>
                <div className="bg-[#fafbfc] dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] p-6 rounded-[32px] soft-shadow-sm">
                  <div className="font-mono text-[13px] text-[#1153ed] dark:text-blue-400 leading-relaxed break-all font-bold">
                    {msg.affected_url || "Target Endpoint"}
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-5">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] border border-[#eaecf0] dark:border-[#2a2b2c]">
                    <Shield size={18} />
                  </div>
                  <h4 className="text-[11px] font-black uppercase tracking-widest text-[#131415] dark:text-white">Technical Evidence</h4>
                </div>
                <div className="bg-[#fafbfc] dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] p-6 rounded-[32px] soft-shadow-sm">
                  <div className="font-mono text-[13px] text-[#475569] dark:text-[#94a3b8] leading-relaxed break-all">
                    <span className="text-[#1153ed] dark:text-blue-400 mr-2 font-black opacity-30 select-none">DATA_VEC:</span>
                    {msg.description || msg.evidence || "Forensic node signature mapping in progress..."}
                  </div>
                </div>
              </div>
            </div>

            {/* Row 2: Strategic Remediation */}
            <div className="flex flex-col gap-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center text-[#1153ed] dark:text-blue-400 border border-[#eaecf0] dark:border-[#2a2b2c]">
                    <Zap size={18} />
                  </div>
                  <h4 className="text-[11px] font-black uppercase tracking-widest text-[#131415] dark:text-white">Strategic Remediation</h4>
                </div>
                <div className="flex items-center gap-1 bg-[#f2f4f7] dark:bg-[#1e293b] p-1 rounded-xl border border-[#eaecf0] dark:border-[#2a2b2c] shadow-sm">
                  <button 
                    onClick={(e) => { e.stopPropagation(); setViewMode("simple"); }}
                    className={cn(
                      "px-5 py-2 text-[9px] font-black uppercase tracking-wider rounded-lg transition-all",
                      viewMode === "simple" ? "bg-[#1153ed] text-white shadow-md shadow-blue-500/20" : "text-[#767a8c] dark:text-[#94a3b8] hover:bg-white dark:hover:bg-slate-800"
                    )}
                  >Summary</button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); setViewMode("technical"); }}
                    className={cn(
                      "px-5 py-2 text-[9px] font-black uppercase tracking-wider rounded-lg transition-all",
                      viewMode === "technical" ? "bg-[#1153ed] text-white shadow-md shadow-blue-500/20" : "text-[#767a8c] dark:text-[#94a3b8] hover:bg-white dark:hover:bg-slate-800"
                    )}
                  >Patch</button>
                </div>
              </div>
              
              <div className="bg-[#f0fdf4] dark:bg-[#064e4b]/20 border border-[#dcfce7] dark:border-[#065f46]/30 p-8 rounded-[32px] soft-shadow-sm transition-all duration-300">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-5 h-5 bg-[#bbf7d0] dark:bg-[#065f46]/50 rounded-full flex items-center justify-center">
                    <Check size={12} className="text-[#16a34a] dark:text-[#34d399] stroke-[3]" />
                  </div>
                  <span className="text-[10px] font-black uppercase tracking-widest text-[#16a34a] dark:text-[#34d399]">
                    {viewMode === "simple" ? "Vulnerability Breakdown" : "Technical Remediation Node"}
                  </span>
                </div>
                <div className="text-[15px] leading-relaxed text-[#064e3b] dark:text-[#a7f3d0] font-medium">
                  <Markdown content={viewMode === "simple" ? (msg.remediation_simple || msg.remediation) : (msg.remediation_technical || msg.remediation)} />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
//  MAIN RESULTS CONTENT
// ─────────────────────────────────────────────────────────────────

function ResultsContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { loading: authLoading } = useAuth();
  const urlFromQuery = searchParams.get("url");
  const scanIdFromQuery = searchParams.get("scanId");

  const [messages, setMessages] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [hackerMode, setHackerMode] = useState(false);
  const pollingRef = useRef(null);

  useEffect(() => {
    if (scanIdFromQuery) {
      startPolling(scanIdFromQuery);
    } else if (urlFromQuery && !isScanning && messages.length === 0) {
      initiateScan(urlFromQuery);
    }

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [urlFromQuery, scanIdFromQuery]);

  const initiateScan = async (targetUrl) => {
    setIsScanning(true);
    try {
      const response = await api.post("/scan/", { target_url: targetUrl });
      if (response.data.success) {
        startPolling(response.data.data.scan_id);
      }
    } catch (error) {
       console.error("Scan failed", error);
       setIsScanning(false);
    }
  };

  const startPolling = (scanId) => {
    setIsScanning(true);
    const checkStatus = async () => {
      try {
        const response = await api.get(`/scan/results/${scanId}/`);
        const data = response.data.data;

        if (data.status === "Completed") {
          if (pollingRef.current) clearInterval(pollingRef.current);
          setScanData(data);
          displayResults(data);
          setIsScanning(false);
        }
      } catch (error) {
        console.error("Polling error:", error);
      }
    };
    checkStatus();
    pollingRef.current = setInterval(checkStatus, 3000);
  };

  const displayResults = (data) => {
    const findings = data.findings || [];
    setMessages(findings.map(f => ({ ...f, type: "issue" })));
  };

  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownloadPDF = async () => {
    const sId = scanIdFromQuery || scanData?.id;
    if (!sId) return;
    
    setIsDownloading(true);
    try {
      const response = await api.get(`/scan/${sId}/download/`, { 
        responseType: "blob",
        timeout: 30000 // 30s timeout for report generation
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `arhmora_report_${sId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error downloading PDF:", error);
      
      // Attempt to extract error message from blob if possible
      if (error.response?.data instanceof Blob) {
        const text = await error.response.data.text();
        try {
          const errorData = JSON.parse(text);
          alert(`Download Failed: ${errorData.error || errorData.message || "Unknown error"}`);
        } catch (e) {
          alert("Download Failed: The server returned an error while generating your report.");
        }
      } else {
        alert("Download Failed: " + (error.response?.data?.message || error.message || "Server unreachable"));
      }
    } finally {
      setIsDownloading(false);
    }
  };

  if (authLoading) return <PageLoader text="Connecting to Neural Cloud..." />;

  if (hackerMode && scanData) {
    return (
      <HackerEyeView 
        findings={scanData.findings} 
        targetUrl={scanData.target_url} 
        onExit={() => setHackerMode(false)} 
      />
    );
  }

  const issueMessages = scanData?.findings || messages;

  return (
    <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans transition-colors duration-300">
      <Sidebar />
      
      <main className="flex-1 ml-[240px] p-8 overflow-y-auto">
        <div className="max-w-6xl mx-auto flex flex-col gap-10">
          
          {/* Enhanced Results Header */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-[#1153ed] dark:text-blue-400 font-black uppercase tracking-[0.25em] text-[10px]">
                <ShieldCheck className="w-4 h-4" />
                Live Threat Intelligence
              </div>
              <h1 className="text-[44px] font-bold text-[#131415] dark:text-white tracking-tight leading-tight">
                Result for <span className="text-[#1153ed] dark:text-blue-400 break-all">{scanData?.target_url || urlFromQuery}</span>
              </h1>
              <div className="flex items-center gap-4 mt-1">
                 <div className="flex items-center gap-2 bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-lg px-3 py-1.5 shadow-sm">
                    <Globe className="w-3.5 h-3.5 text-[#767a8c]" />
                    <span className="text-[11px] font-bold text-[#131415] dark:text-white truncate max-w-[200px]">{scanData?.target_url || urlFromQuery}</span>
                 </div>
                 <div className="h-4 w-px bg-[#eaecf0] dark:bg-[#2a2b2c]" />
                 <span className="text-[11px] font-bold text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest">{new Date().toLocaleDateString()}</span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Button 
                onClick={handleDownloadPDF} 
                disabled={isDownloading || isScanning}
                className="bg-white dark:bg-[#131415] hover:bg-slate-50 dark:hover:bg-[#1e293b] text-[#131415] dark:text-white border border-[#eaecf0] dark:border-[#2a2b2c] px-5 py-5 rounded-xl font-bold shadow-xl shadow-slate-200/20 dark:shadow-none flex items-center gap-2 transition-all active:scale-95 text-sm h-11 disabled:opacity-50"
              >
                {isDownloading ? (
                  <div className="w-4 h-4 border-2 border-[#1153ed] border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Download className="w-4 h-4 text-[#1153ed] dark:text-blue-400" />
                )}
                {isDownloading ? "Generating..." : "Download PDF"}
              </Button>
              <Button 
                onClick={() => setHackerMode(true)} 
                className="bg-[#131415] dark:bg-white dark:text-[#131415] hover:bg-black dark:hover:bg-slate-100 text-white px-5 py-5 rounded-xl font-bold shadow-xl shadow-slate-900/10 active:scale-95 text-sm h-11 flex items-center gap-2"
              >
                <Terminal className="w-4 h-4 text-[#1153ed]" />
                Hacker's Eye View
              </Button>
            </div>
          </div>

          {/* CATEGORIZED VULNERABILITIES SUMMARY */}
          {!isScanning && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in slide-in-from-top-4 duration-700">
              {[
                { 
                  label: "Critical", 
                  count: issueMessages.filter(m => m.severity === "High").length, 
                  color: "text-red-600 dark:text-red-500", 
                  bg: "bg-red-50 dark:bg-red-900/10",
                  border: "border-red-100 dark:border-red-900/20",
                  desc: "Immediate Action Required"
                },
                { 
                  label: "Likely", 
                  count: issueMessages.filter(m => m.severity === "Medium").length, 
                  color: "text-amber-600 dark:text-amber-500", 
                  bg: "bg-amber-50 dark:bg-amber-900/10",
                  border: "border-amber-100 dark:border-amber-900/20",
                  desc: "Probable Vulnerability"
                },
                { 
                  label: "Potential", 
                  count: issueMessages.filter(m => m.severity !== "High" && m.severity !== "Medium").length, 
                  color: "text-[#1153ed] dark:text-blue-400", 
                  bg: "bg-blue-50 dark:bg-blue-900/10",
                  border: "border-blue-100 dark:border-blue-900/20",
                  desc: "Review & Investigation"
                }
              ].map((stat, i) => (
                <div key={i} className={cn(
                  "p-8 rounded-[32px] border flex flex-col gap-4 shadow-sm hover:shadow-md transition-all duration-300",
                  stat.bg, stat.border
                )}>
                  <div className="flex items-center justify-between">
                    <span className={cn("text-[11px] font-black uppercase tracking-[0.3em] opacity-80", stat.color)}>
                      {stat.label}
                    </span>
                    {stat.count > 0 && (
                      <div className={cn("w-2 h-2 rounded-full animate-pulse", stat.color.replace('text', 'bg'))} />
                    )}
                  </div>
                  <div className="flex items-baseline gap-3">
                    <span className={cn("text-5xl font-black tracking-tighter", stat.color)}>{stat.count}</span>
                    <span className="text-sm font-bold text-[#767a8c] dark:text-[#94a3b8] opacity-50 uppercase tracking-widest">Findings</span>
                  </div>
                  <p className="text-[12px] font-semibold text-[#767a8c] dark:text-[#94a3b8] opacity-70">
                    {stat.desc}
                  </p>
                </div>
              ))}
            </div>
          )}

          {/* VULNERABILITIES FEED */}
          <div className="flex flex-col gap-6 mt-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-3">
                <div className="w-1 h-6 bg-[#1153ed] rounded-full" />
                <h2 className="text-[13px] font-black text-[#131415] dark:text-white uppercase tracking-[0.2em]">Detailed Forensic Log</h2>
              </div>
              <div className="flex gap-2 items-center">
                <span className={cn("w-2 h-2 rounded-full", isScanning ? "bg-blue-500 animate-pulse" : "bg-green-500")} />
                <span className="text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest">
                  {isScanning ? "Neural Core Processing" : "Real-time Trace: Active"}
                </span>
              </div>
            </div>

            {isScanning && (
              <div className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] p-10 rounded-[28px] flex flex-col items-center gap-4 shadow-xl shadow-slate-200/20">
                <TechLoader size="md" />
                <p className="text-base font-bold text-[#131415] dark:text-white animate-pulse">Analyzing Neural Vectors...</p>
              </div>
            )}

            {!isScanning && issueMessages.length === 0 && (
              <div className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] p-10 rounded-[28px] flex flex-col items-center text-center gap-4 shadow-xl shadow-slate-200/20">
                <div className="w-16 h-16 bg-emerald-50 dark:bg-emerald-900/20 rounded-[24px] flex items-center justify-center border border-emerald-100 dark:border-emerald-800/30">
                   <ShieldCheck className="w-8 h-8 text-emerald-500" />
                </div>
                <h2 className="text-xl font-bold text-[#131415] dark:text-white">No Vulnerabilities Found</h2>
                <p className="text-[#767a8c] dark:text-[#94a3b8] font-medium text-sm max-w-md">Our neural engines didn&apos;t identify any critical risks for this target. Your security posture appears solid.</p>
              </div>
            )}

            {issueMessages.map((msg, idx) => (
              <FindingListItem key={idx} msg={msg} />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

function ShieldCheck(props) {
  return (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>
  );
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<PageLoader text="Loading Scan Context..." />}>
      <ResultsContent />
    </Suspense>
  );
}
