"use client";

import { useState, useRef, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader, TechLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import {
  Globe,
  Check,
  AlertCircle,
  Activity,
  Info,
  AlertTriangle,
  Sparkles,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

// Actually, defining it in the same file is easier for this edit.

function FindingCard({ msg }) {
  const [viewMode, setViewMode] = useState("simple");

  // Classification labels with softer wording
  const classificationLabels = {
    confirmed: "Confirmed Vulnerability",
    likely: "Likely Vulnerability",
    suspicious: "Suspicious Pattern",
    informational: "Informational",
  };

  // Validation status display
  const validationBadge = {
    validated: {
      text: "✓ Validated",
      bg: "bg-green-100",
      color: "text-green-700",
    },
    partial: { text: "◐ Partial", bg: "bg-amber-100", color: "text-amber-700" },
    failed: {
      text: "✗ Not Validated",
      bg: "bg-red-100",
      color: "text-red-600",
    },
    pending: { text: "○ Pending", bg: "bg-slate-100", color: "text-slate-500" },
  };

  const validation =
    validationBadge[msg.validation_status] || validationBadge.pending;

  return (
    <div
      className={cn(
        "w-full bg-white border p-6 rounded-[28px] shadow-lg shadow-slate-200/20 group hover:shadow-xl hover:-translate-y-1 transition-all duration-300",
        msg.borderColor,
      )}
    >
      <div className="flex items-start gap-5">
        <div
          className={cn(
            "mt-1.5 w-3 h-3 rounded-full shrink-0 shadow-sm animate-pulse",
            msg.color,
          )}
        ></div>
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 flex-wrap">
              {/* Classification label instead of aggressive wording */}
              <span
                className={cn(
                  "text-[10px] font-black uppercase tracking-[0.2em]",
                  msg.textColor,
                )}
              >
                {msg.classification
                  ? classificationLabels[msg.classification]
                  : `${msg.severity} Severity`}
              </span>
              {/* Validation status badge */}
              <span
                className={cn(
                  "text-[9px] font-bold px-2 py-0.5 rounded-full",
                  validation.bg,
                  validation.color,
                )}
              >
                {validation.text}
              </span>
              {msg.isAI && (
                <div className="flex items-center gap-1 bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full border border-indigo-100">
                  <Sparkles className="w-2.5 h-2.5" />
                  <span className="text-[8px] font-black uppercase tracking-wider">
                    AI
                  </span>
                </div>
              )}
            </div>
            {msg.severity === "High" && (
              <AlertTriangle className="w-4 h-4 text-red-500" />
            )}
          </div>
          <h3 className="font-bold text-xl mb-2 tracking-tight text-slate-900 group-hover:text-blue-600 transition-colors">
            {msg.title}
          </h3>

          {/* Multi-factor confidence breakdown */}
          {(msg.total_confidence > 0 || msg.pattern_confidence > 0) && (
            <div className="flex flex-wrap gap-2 mb-3">
              {msg.pattern_confidence > 0 && (
                <span className="px-2 py-0.5 bg-blue-50 text-blue-600 rounded text-[9px] font-bold border border-blue-100">
                  Pattern: {msg.pattern_confidence}%
                </span>
              )}
              {msg.response_confidence > 0 && (
                <span className="px-2 py-0.5 bg-amber-50 text-amber-600 rounded text-[9px] font-bold border border-amber-100">
                  Response: {msg.response_confidence}%
                </span>
              )}
              {msg.exploit_confidence > 0 && (
                <span className="px-2 py-0.5 bg-green-50 text-green-600 rounded text-[9px] font-bold border border-green-100">
                  Exploit: {msg.exploit_confidence}%
                </span>
              )}
              {msg.context_confidence > 0 && (
                <span className="px-2 py-0.5 bg-purple-50 text-purple-600 rounded text-[9px] font-bold border border-purple-100">
                  Context: {msg.context_confidence}%
                </span>
              )}
            </div>
          )}

          {/* Risk metrics */}
          <div className="flex flex-wrap items-center gap-4 mb-4">
            {msg.risk_score > 0 && (
              <div className="flex flex-col gap-1 w-full max-w-[140px]">
                <div className="flex justify-between text-[10px] uppercase font-black tracking-widest text-slate-400">
                  <span>Risk: {msg.risk_score}</span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full",
                      msg.risk_score > 75
                        ? "bg-red-500"
                        : msg.risk_score > 40
                          ? "bg-amber-500"
                          : "bg-blue-500",
                    )}
                    style={{ width: `${msg.risk_score}%` }}
                  />
                </div>
              </div>
            )}
            {msg.total_confidence > 0 && (
              <div className="text-[10px] font-bold text-slate-500 bg-slate-50 px-2 py-1 rounded-md border border-slate-100">
                TOTAL CONFIDENCE: {msg.total_confidence}%
              </div>
            )}
          </div>

          <div className="flex items-start gap-2 bg-slate-50 p-4 rounded-xl mb-4 border border-slate-100/50">
            <Info className="w-4 h-4 text-slate-400 mt-0.5" />
            <p className="text-slate-600 text-sm font-medium leading-relaxed italic">
              &quot;{msg.description}&quot;
            </p>
          </div>

          {/* Dual-Tone Toggle */}
          <div className="flex items-center gap-1 mb-4 bg-slate-100/50 p-1 rounded-lg w-fit">
            <button
              onClick={() => setViewMode("simple")}
              className={cn(
                "px-3 py-1.5 text-[10px] font-black uppercase tracking-wider rounded-md transition-all",
                viewMode === "simple"
                  ? "bg-white shadow-sm text-slate-900"
                  : "text-slate-400 hover:text-slate-600",
              )}
            >
              Simple Explanation
            </button>
            <button
              onClick={() => setViewMode("technical")}
              className={cn(
                "px-3 py-1.5 text-[10px] font-black uppercase tracking-wider rounded-md transition-all",
                viewMode === "technical"
                  ? "bg-white shadow-sm text-slate-900"
                  : "text-slate-400 hover:text-slate-600",
              )}
            >
              Technical Fix
            </button>
          </div>

          <div className="space-y-3">
            <div
              className={cn(
                "p-5 rounded-2xl border transition-colors",
                viewMode === "simple"
                  ? "bg-emerald-50/50 border-emerald-100/50"
                  : "bg-slate-50 border-slate-200",
              )}
            >
              <p
                className={cn(
                  "text-[10px] font-black uppercase tracking-[0.2em] mb-2 flex items-center gap-2",
                  viewMode === "simple" ? "text-emerald-600" : "text-slate-600",
                )}
              >
                {viewMode === "simple" ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Activity className="w-3.5 h-3.5" />
                )}
                {viewMode === "simple"
                  ? "What does this mean?"
                  : "Implementation Details"}
              </p>
              <div
                className={cn(
                  "text-sm font-semibold leading-relaxed",
                  viewMode === "simple"
                    ? "text-emerald-800"
                    : "text-slate-700 font-mono text-[13px]",
                )}
              >
                {viewMode === "simple"
                  ? msg.remediation_simple || msg.remediation
                  : msg.remediation_technical || msg.remediation}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ResultsContent() {
  const { logout, loading: authLoading } = useAuth();
  const searchParams = useSearchParams();
  const router = useRouter();
  const urlFromQuery = searchParams.get("url");
  const scanIdFromQuery = searchParams.get("scanId");

  const [messages, setMessages] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [isError, setIsError] = useState(false);
  const scrollEndRef = useRef(null);
  const pollingRef = useRef(null);

  const scrollToBottom = () => {
    scrollEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

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
    setIsError(false);
    setMessages([{ type: "user", content: targetUrl }]);
    setMessages((prev) => [
      ...prev,
      { type: "progress", content: "Initializing neural scanner..." },
    ]);

    try {
      const response = await api.post("/scan/", { target_url: targetUrl });
      if (response.data.success) {
        const scanId = response.data.data.scan_id;
        startPolling(scanId);
      }
    } catch (error) {
      handleError(
        error.response?.data?.message || "Infrastructure reachability failed.",
      );
    }
  };

  const handleError = (message) => {
    setIsError(true);
    setIsScanning(false);
    if (pollingRef.current) clearInterval(pollingRef.current);
    setMessages((prev) => [
      ...prev,
      {
        type: "error",
        content: message,
      },
    ]);
  };

  const startPolling = (scanId) => {
    setIsScanning(true);
    if (pollingRef.current) clearInterval(pollingRef.current);

    const checkStatus = async () => {
      try {
        const response = await api.get(`/scan/results/${scanId}/`);
        const data = response.data.data;

        if (data.status === "Completed") {
          if (pollingRef.current) clearInterval(pollingRef.current);
          setScanData(data);
          displayResults(data);
        } else if (data.status === "Failed") {
          handleError("Neural handshake failed mid-scan.");
        } else {
          const steps = [
            "Mapping target attack surface...",
            "Discovering input vectors...",
            "Analyzing security headers...",
            "Simulating injection payloads...",
            "Evaluating cryptographic strength...",
          ];
          const currentProgressCount = messages.filter(
            (m) => m.type === "progress",
          ).length;
          if (currentProgressCount < steps.length && Math.random() > 0.6) {
            setMessages((prev) => [
              ...prev,
              { type: "progress", content: steps[currentProgressCount] },
            ]);
          }
        }
      } catch (error) {
        console.error("Polling error:", error);
        // Allow some polling errors (network blips) without immediately failing
        // But if it persists, we might want to fail. For now, just log.
      }
    };

    checkStatus();
    pollingRef.current = setInterval(checkStatus, 3000);
  };

  const displayResults = (data) => {
    const findings = data.findings || [];

    const severityCounts = {
      High: findings.filter((f) => f.severity === "High").length,
      Medium: findings.filter((f) => f.severity === "Medium").length,
      Low: findings.filter((f) => f.severity === "Low").length,
    };

    setMessages((prev) => [
      ...prev,
      {
        type: "summary",
        title: "Analysis Complete",
        text: `Vulnerability assessment finished for ${data.target_url}. We discovered ${findings.length} security events that require attention.`,
        stats: [
          {
            label: "Critical",
            count: severityCounts.High,
            color: "text-red-600",
            bg: "bg-red-500",
          },
          {
            label: "Moderate",
            count: severityCounts.Medium,
            color: "text-amber-600",
            bg: "bg-amber-500",
          },
          {
            label: "Potential",
            count: severityCounts.Low,
            color: "text-indigo-600",
            bg: "bg-indigo-500",
          },
        ],
      },
    ]);

    findings.forEach((finding, i) => {
      const isAI = finding.v_type === "AI-Detected Anomaly";

      // Refined color mapping
      const colorMap = {
        High: {
          bg: "bg-red-500",
          text: "text-red-700",
          border: "border-red-100",
        },
        Medium: {
          bg: "bg-amber-500",
          text: "text-amber-700",
          border: "border-amber-100",
        },
        Low: {
          bg: "bg-indigo-500",
          text: "text-indigo-700",
          border: "border-indigo-100",
        },
      };

      const styles = colorMap[finding.severity] || colorMap.Low;

      setTimeout(() => {
        setMessages((prev) => [
          ...prev,
          {
            type: "issue",
            severity: finding.severity,
            title: finding.v_type,
            description: finding.evidence,
            remediation: finding.remediation,
            isAI: isAI,
            color: styles.bg,
            textColor: styles.text,
            borderColor: styles.border,
            // Risk and priority
            risk_score: finding.risk_score,
            priority_rank: finding.priority_rank,
            endpoint_sensitivity: finding.endpoint_sensitivity,
            // Multi-factor confidence fields
            pattern_confidence: finding.pattern_confidence || 0,
            response_confidence: finding.response_confidence || 0,
            exploit_confidence: finding.exploit_confidence || 0,
            context_confidence: finding.context_confidence || 0,
            total_confidence: finding.total_confidence || 0,
            validation_status: finding.validation_status || "pending",
            classification: finding.classification || "suspicious",
            // Remediation
            remediation_simple: finding.remediation_simple,
            remediation_technical: finding.remediation_technical,
          },
        ]);
      }, i * 400);
    });

    setIsScanning(false);
  };

  if (authLoading) {
    return <PageLoader text="Connecting to Neural Cloud..." />;
  }

  return (
    <div className="flex flex-col min-h-screen bg-[#FDFBFB]">
      <DashHeader />

      <main className="flex-1 overflow-y-auto pt-28 pb-24">
        <div className="max-w-[800px] mx-auto px-4">
          {/* Activity Feed */}
          <div className="flex flex-col gap-6">
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={cn(
                  "flex flex-col animate-in fade-in slide-in-from-bottom-3 duration-500",
                  msg.type === "user" ? "items-end" : "items-center",
                )}
              >
                {msg.type === "user" ? (
                  <div className="bg-white border border-slate-200 px-6 py-4 rounded-[24px] rounded-tr-none shadow-xl shadow-slate-200/20 max-w-[85%] group">
                    <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.2em] text-blue-600 mb-1">
                      <Globe className="w-3.5 h-3.5" />
                      Active Target
                    </div>
                    <span className="font-bold text-slate-900 text-lg group-hover:text-blue-600 transition-colors">
                      {msg.content}
                    </span>
                  </div>
                ) : msg.type === "progress" ? (
                  <div className="w-full bg-white/40 border border-slate-100 p-5 rounded-2xl flex items-center justify-between shadow-sm backdrop-blur-sm border-dashed">
                    <div className="flex items-center gap-4">
                      <div className="relative flex items-center justify-center">
                        <TechLoader size="sm" />
                      </div>
                      <span className="text-slate-600 text-sm font-bold uppercase tracking-widest">
                        {msg.content}
                      </span>
                    </div>
                    <Activity className="w-4 h-4 text-slate-200 animate-pulse" />
                  </div>
                ) : msg.type === "summary" ? (
                  <div className="w-full bg-white border border-slate-200 p-8 rounded-[32px] shadow-2xl shadow-slate-200/30">
                    <div className="flex items-center gap-3 text-emerald-600 font-bold mb-4">
                      <div className="w-8 h-8 bg-emerald-50 rounded-full flex items-center justify-center">
                        <Check className="w-5 h-5" />
                      </div>
                      <span className="text-xl tracking-tight uppercase tracking-widest text-[14px] font-black">
                        {msg.title}
                      </span>
                    </div>
                    <p className="text-slate-600 font-medium text-base mb-8 leading-relaxed">
                      {msg.text}
                    </p>

                    <div className="grid grid-cols-3 gap-4 p-6 bg-slate-50 border border-slate-100 rounded-3xl">
                      {msg.stats.map((stat, i) => (
                        <div key={i} className="flex flex-col items-center">
                          <div className="flex items-center gap-2 mb-2">
                            <div
                              className={cn("w-2 h-2 rounded-full", stat.bg)}
                            ></div>
                            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">
                              {stat.label}
                            </span>
                          </div>
                          <span className="text-3xl font-black text-slate-900 leading-none">
                            {stat.count}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : msg.type === "issue" ? (
                  <FindingCard msg={msg} />
                ) : msg.type === "error" ? (
                  <div className="w-full bg-red-50 border border-red-100 p-8 rounded-[32px] flex flex-col items-center gap-6 shadow-sm text-center">
                    <div className="w-16 h-16 bg-red-100 rounded-2xl flex items-center justify-center text-red-600 mb-2">
                      <AlertCircle className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-red-800 font-bold uppercase tracking-widest text-sm mb-2">
                        Scan Encountered an Error
                      </p>
                      <p className="text-red-700 font-medium max-w-lg mx-auto">
                        {msg.content}
                      </p>
                    </div>
                    <Button
                      onClick={() => router.push("/start-scan")}
                      className="bg-white text-red-600 hover:bg-red-50 border border-red-200 mt-2 font-bold flex items-center gap-2"
                    >
                      <RefreshCw className="w-4 h-4" />
                      Try Again
                    </Button>
                  </div>
                ) : null}
              </div>
            ))}
            <div ref={scrollEndRef} className="h-20" />
          </div>
        </div>
      </main>

      <footer className="fixed bottom-4 left-1/2 -translate-x-1/2 w-fit px-6 py-2 bg-white/60 backdrop-blur-md rounded-full border border-slate-200/50 text-[10px] font-black text-slate-400 uppercase tracking-[0.3em] shadow-sm z-10">
        Encrypted Neural Stream // Arhmora Core v4.2
      </footer>
    </div>
  );
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<PageLoader text="Loading Scan Context..." />}>
      <ResultsContent />
    </Suspense>
  );
}
