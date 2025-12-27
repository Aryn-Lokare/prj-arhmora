// frontend/app/(protected)/dashboard/page.jsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Search, Globe, ArrowRight, Clock, Shield, Sparkles, AlertCircle } from "lucide-react";
import api from "@/lib/api";
import { cn } from "@/lib/utils";

export default function DashboardPage() {
    const { logout, loading: authLoading, user } = useAuth();
    const router = useRouter();
    const [url, setUrl] = useState("");
    const [recentScans, setRecentScans] = useState([]);
    const [loadingScans, setLoadingScans] = useState(true);

    useEffect(() => {
        fetchRecentScans();
    }, []);

    const fetchRecentScans = async () => {
        try {
            const response = await api.get('/scan/history/');
            if (response.data.success) {
                setRecentScans(response.data.data.slice(0, 5));
            }
        } catch (error) {
            console.error("Error fetching recent scans:", error);
        } finally {
            setLoadingScans(false);
        }
    };

    const startScan = (e) => {
        e.preventDefault();
        if (!url) return;
        router.push(`/dashboard/results?url=${encodeURIComponent(url)}`);
    };

    if (authLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-white">
                <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
                    <p className="text-sm font-bold text-slate-400 uppercase tracking-widest font-mono">Authenticating...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex flex-col min-h-screen bg-[#FDFBFB] bg-[radial-gradient(#e5e7eb_1px,transparent_1px)] [background-size:32px_32px]">
            <DashHeader />

            <main className="flex-1 pt-32 pb-32 flex flex-col items-center px-4">
                <div className="max-w-[800px] w-full">
                    {/* Welcome Section */}
                    <div className="mb-12 animate-in fade-in slide-in-from-bottom-2 duration-500">
                        <div className="flex items-center gap-2 mb-2">
                            <div className="bg-blue-50 px-2 py-0.5 rounded-full border border-blue-100 flex items-center gap-1.5">
                                <Sparkles className="w-3 h-3 text-blue-500" />
                                <span className="text-[10px] font-bold text-blue-600 uppercase tracking-wider">Arhmora Security Cloud</span>
                            </div>
                        </div>
                        <h1 className="text-4xl font-bold tracking-tight text-[#0F172A] mb-2">
                            Hello, {user?.first_name || 'Defender'}
                        </h1>
                        <p className="text-slate-500 font-medium">
                            Protect your web infrastructure with AI-driven security assessments.
                        </p>
                    </div>

                    {/* Search Section */}
                    <div className="bg-white border border-slate-200 rounded-[32px] p-8 md:p-12 shadow-2xl shadow-slate-200/40 mb-16 animate-in fade-in slide-in-from-bottom-4 duration-700 delay-100 ring-1 ring-slate-100">
                        <div className="max-w-[600px] mx-auto text-center">
                            <div className="w-16 h-16 bg-blue-50 rounded-2xl flex items-center justify-center mb-6 mx-auto border border-blue-100">
                                <Search className="w-8 h-8 text-blue-500" />
                            </div>
                            <h2 className="text-2xl font-bold mb-3 tracking-tight">
                                Launch a new security scan
                            </h2>
                            <p className="text-slate-500 text-sm font-medium mb-10 leading-relaxed capitalize">
                                Scan for SQL injection, XSS, and security misconfigurations in minutes.
                            </p>

                            <form onSubmit={startScan} className="relative flex items-center group">
                                <div className="absolute left-5 text-slate-400 group-focus-within:text-blue-500 transition-colors">
                                    <Globe className="w-5 h-5" />
                                </div>
                                <input
                                    type="text"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder="https://your-website.com"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl pl-12 pr-40 py-5 text-[16px] font-medium shadow-inner-sm focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500 focus:bg-white transition-all"
                                />
                                <div className="absolute right-2 px-1">
                                    <Button
                                        type="submit"
                                        disabled={!url}
                                        className="bg-[#3B82F6] hover:bg-[#2563EB] text-white px-8 rounded-xl h-12 font-bold shadow-lg shadow-blue-500/20 transition-all active:scale-95 disabled:opacity-50"
                                    >
                                        Scan Now
                                    </Button>
                                </div>
                            </form>
                            <div className="mt-6 flex items-center justify-center gap-6 text-[11px] font-bold text-slate-400 uppercase tracking-widest">
                                <div className="flex items-center gap-1.5"><Shield className="w-3 h-3 text-emerald-500" /> Safe Processing</div>
                                <div className="flex items-center gap-1.5"><Shield className="w-3 h-3 text-emerald-500" /> No SQL Injection</div>
                                <div className="flex items-center gap-1.5"><Shield className="w-3 h-3 text-emerald-500" /> Header Checks</div>
                            </div>
                        </div>
                    </div>

                    {/* Recent Scans Section */}
                    <div className="animate-in fade-in slide-in-from-bottom-4 duration-700 delay-200">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-sm font-bold uppercase tracking-[0.2em] text-slate-400 font-mono flex items-center gap-2">
                                <div className="w-1 h-4 bg-slate-300 rounded-full" />
                                Recent Security Events
                            </h3>
                            <button
                                onClick={() => router.push("/dashboard/history")}
                                className="text-xs font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1 transition-colors uppercase tracking-widest"
                            >
                                View all events <ArrowRight className="w-3 h-3" />
                            </button>
                        </div>

                        {loadingScans ? (
                            <div className="grid grid-cols-1 gap-4">
                                {[1, 2, 3].map(i => (
                                    <div key={i} className="h-20 bg-slate-100 rounded-2xl animate-pulse" />
                                ))}
                            </div>
                        ) : recentScans.length === 0 ? (
                            <div className="bg-white border border-dashed border-slate-300 rounded-3xl p-12 text-center group hover:border-blue-300 transition-colors">
                                <div className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center mb-4 mx-auto text-slate-300">
                                    <Shield className="w-6 h-6" />
                                </div>
                                <p className="text-slate-400 font-bold uppercase tracking-widest text-[11px]">Neural Scan Queue Empty</p>
                                <Button
                                    variant="link"
                                    onClick={() => document.querySelector('input')?.focus()}
                                    className="text-blue-500 font-bold"
                                >
                                    Push your first scan
                                </Button>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 gap-4">
                                {recentScans.map((scan) => (
                                    <div
                                        key={scan.id}
                                        onClick={() => router.push(`/dashboard/results?scanId=${scan.id}`)}
                                        className="bg-white border border-slate-200/80 p-5 rounded-2xl flex items-center justify-between hover:border-blue-400 hover:shadow-xl hover:shadow-blue-500/5 transition-all cursor-pointer group"
                                    >
                                        <div className="flex items-center gap-4">
                                            <div className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center text-slate-400 group-hover:bg-blue-50 group-hover:text-blue-500 transition-colors border border-slate-100">
                                                <Globe className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <p className="text-[15px] font-bold text-slate-900 group-hover:text-blue-600 transition-colors">{scan.target_url}</p>
                                                <div className="flex items-center gap-3 mt-1">
                                                    <p className="text-[11px] text-slate-400 font-bold flex items-center gap-1 uppercase tracking-wider">
                                                        <Clock className="w-3 h-3" />
                                                        {new Date(scan.timestamp).toLocaleDateString()}
                                                    </p>
                                                    <div className="w-1 h-1 bg-slate-200 rounded-full" />
                                                    <div className={cn(
                                                        "text-[9px] font-black px-2 py-0.5 rounded-md uppercase tracking-widest shadow-sm",
                                                        scan.status === 'Completed' ? "bg-emerald-50 text-emerald-600 border border-emerald-100" :
                                                            scan.status === 'Pending' ? "bg-blue-50 text-blue-600 border border-blue-100 animate-pulse" :
                                                                "bg-red-50 text-red-600 border border-red-100"
                                                    )}>
                                                        {scan.status}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            {scan.status === 'Completed' && (
                                                <div className="hidden md:flex flex-col items-end">
                                                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Findings</span>
                                                    <span className="text-sm font-bold text-slate-900">
                                                        {scan.findings?.length || 0} Vulnerabilities
                                                    </span>
                                                </div>
                                            )}
                                            <div className="w-8 h-8 rounded-full flex items-center justify-center group-hover:bg-blue-50 group-hover:text-blue-500 transition-colors">
                                                <ArrowRight className="w-4 h-4 text-slate-300 group-hover:text-blue-500 transition-colors" />
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </main>

            <footer className="py-12 text-center bg-white border-t border-slate-100">
                <div className="max-w-[800px] mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-6 opacity-60">
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-[0.3em]">
                        Arhmora AI Website Scanner // v1.2.0-stable
                    </p>
                    <div className="flex items-center gap-8 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                        <a href="#" className="hover:text-slate-900 transition-colors">Documentation</a>
                        <a href="#" className="hover:text-slate-900 transition-colors">Privacy</a>
                        <a href="#" className="hover:text-slate-900 transition-colors">Support</a>
                    </div>
                </div>
            </footer>
        </div>
    );
}
