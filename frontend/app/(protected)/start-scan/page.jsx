"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Sidebar } from "@/components/layout/sidebar";
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
        <div className="flex min-h-screen bg-background">
            <Sidebar />

            <main className="flex-1 ml-60 flex flex-col items-center justify-center px-4">
                <div className="max-w-[800px] w-full">
                    {/* Search Section */}
                    <div className="bg-white border border-slate-200 rounded-[32px] p-8 md:p-12 shadow-2xl shadow-slate-200/40 animate-in fade-in slide-in-from-bottom-4 duration-700 ring-1 ring-slate-100">
                        <div className="max-w-[600px] mx-auto text-center">
                            <div className="w-16 h-16 bg-[#2D5BFF]/10 rounded-xl flex items-center justify-center mb-6 mx-auto border border-[#2D5BFF]/20">
                                <Search className="w-8 h-8 text-[#2D5BFF]" />
                            </div>
                            <h2 className="text-4xl font-bold mb-3 tracking-tight font-heading text-[#0F172A]">
                                Launch a new security scan
                            </h2>
                            <p className="text-[#64748B] text-sm font-medium mb-10 leading-relaxed capitalize">
                                Scan for SQL injection, XSS, and security misconfigurations in minutes with XGBoost-powered analysis.
                            </p>

                            <form onSubmit={startScan} className="relative flex items-center group">
                                <div className="absolute left-5 text-[#64748B] group-focus-within:text-[#2D5BFF] transition-colors duration-200">
                                    <Globe className="w-5 h-5" />
                                </div>
                                <input
                                    type="text"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder="https://your-website.com"
                                    className="w-full bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl pl-12 pr-40 py-5 text-[16px] font-medium soft-shadow focus:outline-none focus:ring-4 focus:ring-[#2D5BFF]/10 focus:border-[#2D5BFF] focus:bg-white transition-all duration-200"
                                />
                                <div className="absolute right-2 px-1">
                                    <Button
                                        type="submit"
                                        disabled={!url}
                                        className="bg-[#2D5BFF] hover:bg-[#1D4ED8] text-white px-8 rounded-xl h-12 font-bold soft-shadow transition-all duration-200 active:scale-95 disabled:opacity-50"
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
