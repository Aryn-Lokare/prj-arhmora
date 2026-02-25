"use client";

import { useEffect, useState, useRef, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import api from "@/lib/api";
import Image from "next/image";
import { AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

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
                    setError("Text has failed to generate result");
                }
            } catch (err) {
                console.error("Scan initiation failed:", err);
                setError("Text has failed to generate result");
            }
        };

        const addLog = (msg) => {
            setLogs(prev => {
                if (prev[prev.length - 1] === msg) return prev;
                return [...prev.slice(-4), msg]; // Keep last 5 logs for a clean feed
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
                        }, 1000);
                    } else if (data.status === "Failed") {
                        clearInterval(pollingInterval);
                        setError("Text has failed to generate result");
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
        <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans overflow-hidden transition-colors duration-300">
            <Sidebar showNewScan={false} />

<main className="flex-1 ml-[280px] flex flex-col items-center justify-center p-8 relative">
                <style dangerouslySetInnerHTML={{ __html: `
                    @keyframes flicker {
                        0%, 19.999%, 22%, 62.999%, 64%, 64.999%, 70%, 100% {
                            opacity: 1;
                            filter: drop-shadow(0 0 10px rgba(17, 83, 237, 0.3));
                        }
                        20%, 21.999%, 63%, 63.999%, 65%, 69.999% {
                            opacity: 0.4;
                            filter: drop-shadow(0 0 2px rgba(17, 83, 237, 0.1));
                        }
                    }
                    .logo-flicker {
                        animation: flicker 4s infinite step-end;
                    }
                    .log-appear {
                        animation: logSlide 0.3s ease-out forwards;
                    }
                    @keyframes logSlide {
                        from { opacity: 0; transform: translateY(5px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                `}} />

                <div className="flex flex-col items-center w-full max-w-md">
                    {error ? (
                        <div className="flex flex-col items-center animate-in fade-in zoom-in duration-500">
                            <div className="w-20 h-20 bg-red-100 dark:bg-red-900/20 rounded-[28px] flex items-center justify-center mb-8 border border-red-200 dark:border-red-800/30">
                                <AlertCircle className="w-10 h-10 text-red-500" />
                            </div>
                            <h2 className="text-2xl font-bold text-[#131415] dark:text-white mb-4">Initialisation Failed</h2>
                            <p className="text-red-500 font-bold text-[15px] p-4 bg-red-50 dark:bg-red-950/20 rounded-2xl border border-red-100 dark:border-red-900/30">
                                {error}
                            </p>
                            <button 
                                onClick={() => router.push("/start-scan")}
                                className="mt-8 text-[#1153ed] dark:text-blue-400 font-bold text-sm uppercase tracking-widest hover:underline"
                            >
                                Return to Console
                            </button>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center w-full">
                            <div className="relative mb-20">
                                <div className="absolute inset-0 bg-[#1153ed] opacity-20 blur-[60px] rounded-full scale-150 animate-pulse"></div>
                                <div className="relative logo-flicker">
                                    <Image 
                                        src="/Group 17.png" 
                                        alt="Arhmora" 
                                        width={300} 
                                        height={80} 
                                        className="h-20 w-auto object-contain"
                                    />
                                </div>
                            </div>
                            
                            {/* Terminal-style Log Feed */}
                            <div className="w-full bg-[#f2f4f7] dark:bg-[#131415] rounded-[32px] p-8 relative overflow-hidden group border border-transparent dark:border-[#2a2b2c]">
                                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#1153ed] to-transparent opacity-20"></div>
                                
                                <div className="flex flex-col gap-3">
                                    {logs.map((log, i) => (
                                        <div 
                                            key={i} 
                                            className={cn(
                                                "text-xs tracking-tight flex items-start gap-3 log-appear font-mono",
                                                i === logs.length - 1 ? "text-[#1153ed] dark:text-blue-400" : "text-[#767a8c] dark:text-[#94a3b8]"
                                            )}
                                        >
                                            <span className="shrink-0 opacity-40 select-none">{">"}</span>
                                            <span className={cn(
                                                i === logs.length - 1 ? "font-bold" : "font-medium"
                                            )}>{log}</span>
                                        </div>
                                    ))}
                                    
                                    <div className="flex items-center gap-2 mt-2">
                                        <div className="w-1 h-3 bg-[#1153ed] dark:bg-blue-400 animate-pulse"></div>
                                        <span className="text-[10px] text-[#1153ed] dark:text-blue-400 font-black uppercase tracking-widest animate-pulse">Processing...</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Subtle text at bottom */}
                <div className="absolute bottom-12 left-1/2 -translate-x-1/2 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.5em] opacity-40">
                    Neural Engine v4.2 // Protocol Handshake
                </div>
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
