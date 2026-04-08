"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState, useRef, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import api from "@/lib/api";
import Image from "next/image";
import { AlertCircle, Terminal, Cpu, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

const ScanningBeam = () => (
    <motion.div
        initial={{ left: "-100%" }}
        animate={{ left: "100%" }}
        transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
        className="absolute top-0 h-full w-32 bg-gradient-to-r from-transparent via-blue-500/10 to-transparent skew-x-[30deg] pointer-events-none z-10"
    />
);

function ScanningContent() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const { loading: authLoading } = useAuth();
    const [error, setError] = useState(null);
    const [logs, setLogs] = useState(["[SYSTEM] Initializing neural handshake..."]);
    const targetUrl = searchParams.get("url");
    const scanInitiated = useRef(false);

    useEffect(() => {
        if (!targetUrl || scanInitiated.current) return;
        scanInitiated.current = true;

        let pollingInterval = null;

        const initiateScan = async () => {
            try {
                const response = await api.post("/scan/", { target_url: targetUrl });
                if (response.data.success) {
                    const scanId = response.data.data.scan_id;
                    addLog(`[SYSTEM] Scan initiated (ID: ${scanId.toString().slice(0, 8)})`);
                    startPolling(scanId);
                } else {
                    setError("Scan initiation failed to return success");
                }
            } catch (err) {
                console.error("Scan initiation failed:", err);
                const backendMsg = err.response?.data?.message;
                setError(backendMsg || "Failed to connect to the scanning engine");
            }
        };

        const addLog = (msg) => {
            setLogs(prev => {
                if (prev[prev.length - 1] === msg) return prev;
                return [...prev.slice(-4), msg]; 
            });
        };

        const startPolling = (scanId) => {
            pollingInterval = setInterval(async () => {
                try {
                    const response = await api.get(`/scan/results/${scanId}/`);
                    const data = response.data.data;

                    if (data.current_step) {
                        addLog(`[ENGINE] ${data.current_step}`);
                    }

                    if (data.status === "Completed") {
                        addLog("[SYSTEM] Neural audit complete. Handshaking results...");
                        clearInterval(pollingInterval);
                        setTimeout(() => {
                            router.push(`/scan-result?scanId=${scanId}`);
                        }, 1200);
                    } else if (data.status === "Failed") {
                        clearInterval(pollingInterval);
                        setError("Engine encountered a critical failure during analysis");
                    }
                } catch (err) {
                    console.error("Polling failed:", err);
                }
            }, 1500);
        };

        initiateScan();

        return () => {
            if (pollingInterval) clearInterval(pollingInterval);
        };
    }, [targetUrl, router]);

    if (authLoading) return <PageLoader text="Syncing Security Cloud..." />;

    return (
        <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans overflow-hidden transition-colors duration-500">
            <Sidebar showNewScan={false} />

            <main className="flex-1 ml-[280px] flex flex-col items-center justify-center p-8 relative">
                {/* Background Ambient Glows */}
                <motion.div 
                    animate={{ 
                        scale: [1, 1.2, 1],
                        opacity: [0.1, 0.2, 0.1]
                    }}
                    transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                    className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-500/20 blur-[120px] rounded-full pointer-events-none"
                />

                <div className="flex flex-col items-center w-full max-w-lg relative z-10">
                    {error ? (
                        <motion.div 
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="flex flex-col items-center"
                        >
                            <div className="w-20 h-20 bg-red-100 dark:bg-red-900/20 rounded-[28px] flex items-center justify-center mb-8 border border-red-200 dark:border-red-800/30">
                                <AlertCircle className="w-10 h-10 text-red-500" />
                            </div>
                            <h2 className="text-2xl font-bold text-[#131415] dark:text-white mb-4">Initialisation Failed</h2>
                            <p className="text-red-500 font-bold text-[15px] p-4 bg-red-50 dark:bg-red-950/20 rounded-2xl border border-red-100 dark:border-red-900/30 text-center">
                                {error}
                            </p>
                            <button 
                                onClick={() => router.push("/start-scan")}
                                className="mt-8 text-[#1153ed] dark:text-blue-400 font-bold text-sm uppercase tracking-widest hover:underline flex items-center gap-2"
                            >
                                <Terminal className="w-4 h-4" /> Return to Console
                            </button>
                        </motion.div>
                    ) : (
                        <div className="flex flex-col items-center w-full">
                            <div className="relative mb-20 group">
                                <motion.div 
                                    animate={{ rotate: 360 }}
                                    transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                                    className="absolute -inset-10 border border-blue-500/20 rounded-full border-dashed pointer-events-none"
                                />
                                <motion.div 
                                    animate={{ rotate: -360 }}
                                    transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
                                    className="absolute -inset-16 border border-blue-500/10 rounded-full border-dashed pointer-events-none"
                                />
                                
                                <div className="absolute inset-0 bg-[#1153ed] opacity-20 blur-[60px] rounded-full scale-150 animate-pulse"></div>
                                <motion.div 
                                    animate={{ 
                                        opacity: [1, 0.7, 1],
                                        filter: [
                                            "drop-shadow(0 0 10px rgba(17, 83, 237, 0.3))",
                                            "drop-shadow(0 0 20px rgba(17, 83, 237, 0.5))",
                                            "drop-shadow(0 0 10px rgba(17, 83, 237, 0.3))"
                                        ]
                                    }}
                                    transition={{ duration: 4, repeat: Infinity }}
                                    className="relative overflow-hidden rounded-xl p-4"
                                >
                                    <Image 
                                        src="/Group 17.png" 
                                        alt="Arhmora" 
                                        width={300} 
                                        height={80} 
                                        className="h-20 w-auto object-contain relative z-20"
                                    />
                                    <ScanningBeam />
                                </motion.div>
                            </div>
                            
                            {/* Terminal-style Log Feed */}
                            <div className="w-full bg-white dark:bg-[#131415] rounded-[32px] p-8 relative overflow-hidden group border border-[#e2e8f0] dark:border-[#2a2b2c] shadow-2xl shadow-blue-500/5">
                                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#1153ed] to-transparent opacity-30"></div>
                                
                                <div className="flex flex-col gap-4 min-h-[140px]">
                                    <AnimatePresence mode="popLayout">
                                        {logs.map((log, i) => (
                                            <motion.div 
                                                key={log + i} 
                                                initial={{ opacity: 0, y: 10, filter: "blur(4px)" }}
                                                animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                                                exit={{ opacity: 0, scale: 0.95 }}
                                                transition={{ duration: 0.4, ease: "easeOut" }}
                                                className={cn(
                                                    "text-xs tracking-tight flex items-start gap-4 font-mono",
                                                    i === logs.length - 1 ? "text-[#1153ed] dark:text-blue-400" : "text-[#767a8c] dark:text-[#94a3b8]"
                                                )}
                                            >
                                                <span className="shrink-0 opacity-40 select-none">
                                                    {i === logs.length - 1 ? <Cpu className="w-3 h-3 animate-spin" /> : ">"}
                                                </span>
                                                <span className={cn(
                                                    "leading-relaxed",
                                                    i === logs.length - 1 ? "font-bold" : "font-medium"
                                                )}>{log}</span>
                                            </motion.div>
                                        ))}
                                    </AnimatePresence>
                                    
                                    <motion.div 
                                        animate={{ opacity: [0.4, 1, 0.4] }}
                                        transition={{ duration: 1.5, repeat: Infinity }}
                                        className="flex items-center gap-2 mt-4"
                                    >
                                        <div className="w-1.5 h-4 bg-[#1153ed] dark:bg-blue-400 rounded-full shadow-[0_0_8px_rgba(17,83,237,0.5)]"></div>
                                        <span className="text-[10px] text-[#1153ed] dark:text-blue-400 font-black uppercase tracking-[0.2em]">Neural Processing in Progress...</span>
                                    </motion.div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Subtle text at bottom */}
                <motion.div 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 0.4 }}
                    transition={{ delay: 1 }}
                    className="absolute bottom-12 left-1/2 -translate-x-1/2 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.5em] flex items-center gap-4"
                >
                    <span>Neural Engine v4.2</span>
                    <span className="w-1 h-1 bg-blue-500 rounded-full opacity-50"></span>
                    <span>Protocol Handshake 0x7F</span>
                </motion.div>
            </main>
        </div>
    );
}

export default function ScanningPage() {
    return (
        <Suspense fallback={<PageLoader text="Handshaking..." />}>
            <ScanningContent />
        </Suspense>
    );
}
