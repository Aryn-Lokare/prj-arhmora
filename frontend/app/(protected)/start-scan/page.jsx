"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Search, Globe, Shield } from "lucide-react";

export default function StartScanPage() {
    const { logout, loading: authLoading, user } = useAuth();
    const router = useRouter();
    const [url, setUrl] = useState("");

    const startScan = (e) => {
        e.preventDefault();
        if (!url) return;
        router.push(`/scan-result?url=${encodeURIComponent(url)}`);
    };

    if (authLoading) {
        return <PageLoader text="Authenticating..." />;
    }

    return (
        <div className="flex flex-col min-h-screen bg-[#FDFBFB] bg-[radial-gradient(#e5e7eb_1px,transparent_1px)] [background-size:32px_32px]">
            <DashHeader />

            <main className="flex-1 flex flex-col items-center justify-center px-4">
                <div className="max-w-[800px] w-full">
                    {/* Search Section */}
                    <div className="bg-white border border-slate-200 rounded-[32px] p-8 md:p-12 shadow-2xl shadow-slate-200/40 animate-in fade-in slide-in-from-bottom-4 duration-700 ring-1 ring-slate-100">
                        <div className="max-w-[600px] mx-auto text-center">
                            <div className="w-16 h-16 bg-blue-50 rounded-2xl flex items-center justify-center mb-6 mx-auto border border-blue-100">
                                <Search className="w-8 h-8 text-blue-500" />
                            </div>
                            <h2 className="text-2xl font-bold mb-3 tracking-tight">
                                Launch a new security scan
                            </h2>
                            <p className="text-slate-500 text-sm font-medium mb-10 leading-relaxed capitalize">
                                Scan for SQL injection, XSS, and security misconfigurations in minutes with XGBoost-powered analysis.
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
