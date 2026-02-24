"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { Sidebar } from "@/components/layout/sidebar";
import { Search, Globe, Shield, ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";

export default function StartScanPage() {
  const { loading: authLoading, user } = useAuth();
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [urlError, setUrlError] = useState("");

  const normalizeUrl = (raw) => {
    const trimmed = raw.trim();
    if (!trimmed) return "";
    if (!/^https?:\/\//i.test(trimmed)) {
      return "https://" + trimmed;
    }
    return trimmed;
  };

  const startScan = (e) => {
    e.preventDefault();
    setUrlError("");
    const normalized = normalizeUrl(url);
    if (!normalized) return;
    try {
      const parsed = new URL(normalized);
      if (!parsed.hostname) {
        setUrlError("Please enter a valid URL");
        return;
      }
    } catch {
      setUrlError("Please enter a valid URL");
      return;
    }
    router.push(`/scanning?url=${encodeURIComponent(normalized)}`);
  };

  if (authLoading) {
    return <PageLoader text="Syncing Security Cloud..." />;
  }

  return (
    <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans overflow-hidden transition-colors duration-300">
      <Sidebar showNewScan={false} />

      <main className="flex-1 ml-[280px] flex flex-col h-screen relative">
        {/* Centered Greeting Section */}
        <div className="flex-1 flex flex-col items-center justify-center p-12 text-center animate-in fade-in duration-1000 -mt-20">
            <div className="w-20 h-20 bg-[#1153ed]/10 dark:bg-blue-900/20 rounded-[24px] flex items-center justify-center mb-10 border border-[#1153ed]/20 dark:border-blue-800/30 shadow-sm">
                <Shield className="w-10 h-10 text-[#1153ed] dark:text-blue-400" />
            </div>
            <p className="text-[#1153ed] dark:text-blue-400 text-[11px] font-black uppercase tracking-[0.3em] mb-6">Protocol: Advanced Scanning</p>
            <h1 className="text-5xl md:text-6xl font-bold text-[#131415] dark:text-white leading-tight tracking-tight max-w-3xl">
                Ready to secure your <span className="text-[#1153ed] dark:text-blue-400">Digital Assets?</span>
            </h1>
            <p className="text-[#767a8c] dark:text-[#94a3b8] mt-8 font-medium max-w-xl text-lg leading-relaxed">
                Enter the target URL below to launch an AI-powered vulnerability audit. 
                Our neural engines will scan for SQLi, XSS, and misconfigurations.
            </p>
        </div>

        {/* Bottom Input Area (ChatGPT style) */}
        <div className="max-w-4xl w-full mx-auto p-12 pb-16 pt-0">
            <form onSubmit={startScan} className="relative group">
                <div className="absolute left-6 top-1/2 -translate-y-1/2 text-[#767a8c] dark:text-[#94a3b8] group-focus-within:text-[#1153ed] dark:group-focus-within:text-blue-400 transition-colors">
                    <Globe size={20} />
                </div>
                
                <input
                    type="text"
                    value={url}
                    onChange={(e) => { setUrl(e.target.value); setUrlError(""); }}
                    placeholder="https://your-target-url.com"
                    className={cn(
                        "w-full bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[24px] pl-16 pr-44 py-6 text-[16px] font-medium shadow-2xl dark:shadow-none focus:outline-none focus:ring-4 focus:ring-[#1153ed]/5 focus:border-[#1153ed] dark:focus:border-blue-500 text-[#131415] dark:text-white transition-all duration-300",
                        urlError && "border-red-400 focus:ring-red-500/5 focus:border-red-400 dark:border-red-500"
                    )}
                />

                <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-3">
                    {url && (
                        <button 
                            type="button" 
                            onClick={() => setUrl("")}
                            className="p-2 text-[#767a8c] dark:text-[#94a3b8] hover:text-[#131415] dark:hover:text-white transition-colors"
                        >
                            <Search size={18} />
                        </button>
                    )}
                    <button
                        type="submit"
                        disabled={!url}
                        className="bg-[#1153ed] dark:bg-blue-600 hover:bg-[#0044e6] dark:hover:bg-blue-500 text-white px-8 py-3.5 rounded-2xl font-bold text-sm shadow-lg active:scale-95 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                        Start Scan
                        <ArrowUpRight size={18} />
                    </button>
                </div>
            </form>

            {urlError && (
                <p className="mt-4 text-[13px] text-red-500 font-bold text-center flex items-center justify-center gap-2 animate-in fade-in slide-in-from-top-2 duration-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                    {urlError}
                </p>
            )}


        </div>
      </main>
    </div>
  );
}
