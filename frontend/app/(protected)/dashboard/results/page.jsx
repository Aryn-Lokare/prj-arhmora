// frontend/app/(protected)/dashboard/results/page.jsx

"use client";

import { useState, useRef, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Plus, Globe, ChevronRight, Check, AlertCircle, Shield, ExternalLink, Activity, Info, AlertTriangle, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

function ResultsContent() {
    const { logout, loading: authLoading } = useAuth();
    const searchParams = useSearchParams();
    const router = useRouter();
    const urlFromQuery = searchParams.get("url");
    const scanIdFromQuery = searchParams.get("scanId");

    const [messages, setMessages] = useState([]);
    const [isScanning, setIsScanning] = useState(false);
    const [scanData, setScanData] = useState(null);
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
        setMessages([{ type: "user", content: targetUrl }]);
        setMessages(prev => [...prev, { type: "progress", content: "Initializing neural scanner..." }]);

        try {
            const response = await api.post('/scan/', { target_url: targetUrl });
            if (response.data.success) {
                const scanId = response.data.data.scan_id;
                startPolling(scanId);
            }
        } catch (error) {
            setMessages(prev => [...prev, {
                type: "error",
                content: error.response?.data?.message || "Infrastructure reachability failed."
            }]);
            setIsScanning(false);
        }
    };

    const startPolling = (scanId) => {
        setIsScanning(true);
        if (pollingRef.current) clearInterval(pollingRef.current);

        const checkStatus = async () => {
            try {
                const response = await api.get(`/scan/results/${scanId}/`);
                const data = response.data.data;

                if (data.status === 'Completed') {
                    if (pollingRef.current) clearInterval(pollingRef.current);
                    setScanData(data);
                    displayResults(data);
                } else if (data.status === 'Failed') {
                    if (pollingRef.current) clearInterval(pollingRef.current);
                    setMessages(prev => [...prev, { type: "error", content: "Neural handshake failed mid-scan." }]);
                    setIsScanning(false);
                } else {
                    const steps = [
                        "Mapping target attack surface...",
                        "Discovering input vectors...",
                        "Analyzing security headers...",
                        "Simulating injection payloads...",
                        "Evaluating cryptographic strength..."
                    ];
                    const currentProgressCount = messages.filter(m => m.type === "progress").length;
                    if (currentProgressCount < steps.length && Math.random() > 0.6) {
                        setMessages(prev => [...prev, { type: "progress", content: steps[currentProgressCount] }]);
                    }
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

        const severityCounts = {
            High: findings.filter(f => f.severity === 'High').length,
            Medium: findings.filter(f => f.severity === 'Medium').length,
            Low: findings.filter(f => f.severity === 'Low').length,
        };

        setMessages(prev => [...prev, {
            type: "summary",
            title: "Analysis Complete",
            text: `Vulnerability assessment finished for ${data.target_url}. We discovered ${findings.length} security events that require attention.`,
            stats: [
                { label: "Critical", count: severityCounts.High, color: "text-red-600", bg: "bg-red-500" },
                { label: "Moderate", count: severityCounts.Medium, color: "text-amber-600", bg: "bg-amber-500" },
                { label: "Potential", count: severityCounts.Low, color: "text-indigo-600", bg: "bg-indigo-500" }
            ]
        }]);

        findings.forEach((finding, i) => {
            const isAI = finding.v_type === 'AI-Detected Anomaly';

            // Refined color mapping
            const colorMap = {
                High: { bg: 'bg-red-500', text: 'text-red-700', border: 'border-red-100' },
                Medium: { bg: 'bg-amber-500', text: 'text-amber-700', border: 'border-amber-100' },
                Low: { bg: 'bg-indigo-500', text: 'text-indigo-700', border: 'border-indigo-100' }
            };

            const styles = colorMap[finding.severity] || colorMap.Low;

            setTimeout(() => {
                setMessages(prev => [...prev, {
                    type: "issue",
                    severity: finding.severity,
                    title: finding.v_type,
                    description: finding.evidence,
                    remediation: finding.remediation,
                    isAI: isAI,
                    color: styles.bg,
                    textColor: styles.text,
                    borderColor: styles.border
                }]);
            }, i * 400);
        });

        setIsScanning(false);
    };

    if (authLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-white">
                <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
            </div>
        );
    }

    return (
        <div className="flex flex-col min-h-screen bg-[#FDFBFB]">
            <DashHeader />

            <main className="flex-1 overflow-y-auto pt-28 pb-24">
                <div className="max-w-[800px] mx-auto px-4">

                    {/* Activity Feed */}
                    <div className="flex flex-col gap-6">
                        {messages.map((msg, idx) => (
                            <div key={idx} className={cn(
                                "flex flex-col animate-in fade-in slide-in-from-bottom-3 duration-500",
                                msg.type === "user" ? "items-end" : "items-center"
                            )}>
                                {msg.type === "user" ? (
                                    <div className="bg-white border border-slate-200 px-6 py-4 rounded-[24px] rounded-tr-none shadow-xl shadow-slate-200/20 max-w-[85%] group">
                                        <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.2em] text-blue-600 mb-1">
                                            <Globe className="w-3.5 h-3.5" />
                                            Active Target
                                        </div>
                                        <span className="font-bold text-slate-900 text-lg group-hover:text-blue-600 transition-colors">{msg.content}</span>
                                    </div>
                                ) : msg.type === "progress" ? (
                                    <div className="w-full bg-white/40 border border-slate-100 p-5 rounded-2xl flex items-center justify-between shadow-sm backdrop-blur-sm border-dashed">
                                        <div className="flex items-center gap-4">
                                            <div className="relative flex items-center justify-center">
                                                <div className="w-6 h-6 border-2 border-slate-100 rounded-full"></div>
                                                <div className="absolute inset-0 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                                            </div>
                                            <span className="text-slate-600 text-sm font-bold uppercase tracking-widest">{msg.content}</span>
                                        </div>
                                        <Activity className="w-4 h-4 text-slate-200 animate-pulse" />
                                    </div>
                                ) : msg.type === "summary" ? (
                                    <div className="w-full bg-white border border-slate-200 p-8 rounded-[32px] shadow-2xl shadow-slate-200/30">
                                        <div className="flex items-center gap-3 text-emerald-600 font-bold mb-4">
                                            <div className="w-8 h-8 bg-emerald-50 rounded-full flex items-center justify-center">
                                                <Check className="w-5 h-5" />
                                            </div>
                                            <span className="text-xl tracking-tight uppercase tracking-widest text-[14px] font-black">{msg.title}</span>
                                        </div>
                                        <p className="text-slate-600 font-medium text-base mb-8 leading-relaxed">{msg.text}</p>

                                        <div className="grid grid-cols-3 gap-4 p-6 bg-slate-50 border border-slate-100 rounded-3xl">
                                            {msg.stats.map((stat, i) => (
                                                <div key={i} className="flex flex-col items-center">
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <div className={cn("w-2 h-2 rounded-full", stat.bg)}></div>
                                                        <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">{stat.label}</span>
                                                    </div>
                                                    <span className="text-3xl font-black text-slate-900 leading-none">{stat.count}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ) : msg.type === "issue" ? (
                                    <div className={cn(
                                        "w-full bg-white border p-6 rounded-[28px] shadow-lg shadow-slate-200/20 group hover:shadow-xl hover:-translate-y-1 transition-all duration-300",
                                        msg.borderColor
                                    )}>
                                        <div className="flex items-start gap-5">
                                            <div className={cn("mt-1.5 w-3 h-3 rounded-full shrink-0 shadow-sm animate-pulse", msg.color)}></div>
                                            <div className="flex-1">
                                                <div className="flex items-center justify-between mb-2">
                                                    <div className="flex items-center gap-2">
                                                        <span className={cn("text-[10px] font-black uppercase tracking-[0.2em]", msg.textColor)}>
                                                            {msg.severity} PRIORITY THREAT
                                                        </span>
                                                        {msg.isAI && (
                                                            <div className="flex items-center gap-1 bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full border border-indigo-100 animate-pulse">
                                                                <Sparkles className="w-2.5 h-2.5" />
                                                                <span className="text-[8px] font-black uppercase tracking-wider">Neural Intelligence</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                    {msg.severity === 'High' && <AlertTriangle className="w-4 h-4 text-red-500" />}
                                                </div>
                                                <h3 className="font-bold text-xl mb-2 tracking-tight text-slate-900 group-hover:text-blue-600 transition-colors">{msg.title}</h3>
                                                <div className="flex items-start gap-2 bg-slate-50 p-4 rounded-xl mb-6 mt-4 border border-slate-100/50">
                                                    <Info className="w-4 h-4 text-slate-400 mt-0.5" />
                                                    <p className="text-slate-600 text-sm font-medium leading-relaxed italic">&quot;{msg.description}&quot;</p>
                                                </div>

                                                <div className="space-y-3">
                                                    <div className="bg-emerald-50/50 p-5 rounded-2xl border border-emerald-100/50">
                                                        <p className="text-[10px] font-black text-emerald-600 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                                                            <Check className="w-3.5 h-3.5" /> Suggested Remediation
                                                        </p>
                                                        <p className="text-sm font-semibold text-emerald-800 leading-relaxed">{msg.remediation}</p>
                                                    </div>
                                                    <div className="flex items-center justify-end px-2">
                                                        <button className="text-[11px] font-black text-slate-400 uppercase tracking-widest hover:text-blue-600 transition-colors flex items-center gap-1.5 group/btn">
                                                            Comprehensive fixing guide <ExternalLink className="w-3 h-3 group-hover/btn:translate-x-0.5 group-hover/btn:-translate-y-0.5 transition-transform" />
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ) : msg.type === "error" ? (
                                    <div className="w-full bg-red-50 border border-red-100 p-6 rounded-[24px] flex items-center gap-4 shadow-sm">
                                        <div className="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center text-red-600">
                                            <AlertCircle className="w-6 h-6" />
                                        </div>
                                        <div>
                                            <p className="text-red-800 font-bold uppercase tracking-widest text-xs">Analysis Failed</p>
                                            <span className="text-red-700 text-sm font-medium">{msg.content}</span>
                                        </div>
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
        <Suspense fallback={
            <div className="min-h-screen flex items-center justify-center bg-white">
                <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
            </div>
        }>
            <ResultsContent />
        </Suspense>
    );
}
