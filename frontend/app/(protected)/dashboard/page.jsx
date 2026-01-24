"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Globe, ArrowRight, Clock, Shield, Sparkles, AlertTriangle, CheckCircle, Activity } from "lucide-react";
import api from "@/lib/api";
import { cn } from "@/lib/utils";

export default function DashboardPage() {
    const { logout, loading: authLoading, user } = useAuth();
    const router = useRouter();
    const [recentScans, setRecentScans] = useState([]);
    const [loadingScans, setLoadingScans] = useState(true);
    const [stats, setStats] = useState(null);
    const [loadingStats, setLoadingStats] = useState(true);

    useEffect(() => {
        fetchRecentScans();
        fetchDashboardStats();
    }, []);

    const fetchDashboardStats = async () => {
        try {
            const response = await api.get('/scan/dashboard-stats/');
            if (response.data.success) {
                setStats(response.data.data);
            }
        } catch (error) {
            console.error("Error fetching stats:", error);
        } finally {
            setLoadingStats(false);
        }
    };

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

    if (authLoading) {
        return <PageLoader text="Verifying Identity..." />;
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
                                <span className="text-[10px] font-bold text-blue-600 uppercase tracking-wider">XGBoost-Powered Security Cloud</span>
                            </div>
                        </div>
                        <h1 className="text-4xl font-bold tracking-tight text-[#0F172A] mb-2">
                            Hello, {user?.first_name || 'Defender'}
                        </h1>
                        <p className="text-slate-500 font-medium">
                            Here is an overview of your security landscape.
                        </p>
                    </div>

                    {/* Action Bar */}
                    <div className="flex justify-end mb-8">
                        <Button
                            onClick={() => router.push('/start-scan')}
                            className="bg-[#3B82F6] hover:bg-[#2563EB] text-white px-6 rounded-xl h-10 font-bold shadow-lg shadow-blue-500/20 transition-all active:scale-95 flex items-center gap-2"
                        >
                            <Globe className="w-4 h-4" />
                            New Scan
                        </Button>
                    </div>

                    {/* Risk Score & Top Fixes */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
                        {/* Risk Score Card */}
                        <div className="bg-white border border-slate-200 rounded-[24px] p-6 shadow-sm relative overflow-hidden group">
                            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                                <Activity className="w-24 h-24 text-blue-600" />
                            </div>
                            <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 mb-6 flex items-center gap-2">
                                <Shield className="w-3 h-3" /> Security Health
                            </h3>
                            
                            {loadingStats ? (
                                <div className="h-32 animate-pulse bg-slate-50 rounded-xl" />
                            ) : (
                                <div className="flex flex-col items-center justify-center py-4">
                                    <div className="relative w-32 h-32 flex items-center justify-center">
                                        {/* Background Circle */}
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle
                                                cx="64"
                                                cy="64"
                                                r="56"
                                                stroke="currentColor"
                                                strokeWidth="12"
                                                fill="transparent"
                                                className="text-slate-100"
                                            />
                                            {/* Progress Circle */}
                                            <circle
                                                cx="64"
                                                cy="64"
                                                r="56"
                                                stroke="currentColor"
                                                strokeWidth="12"
                                                fill="transparent"
                                                strokeDasharray={351.86}
                                                strokeDashoffset={351.86 - (351.86 * stats?.risk_score || 0) / 100}
                                                className={cn(
                                                    "transition-all duration-1000 ease-out",
                                                    stats?.risk_score >= 80 ? "text-emerald-500" :
                                                    stats?.risk_score >= 50 ? "text-amber-500" : "text-red-500"
                                                )}
                                                strokeLinecap="round"
                                            />
                                        </svg>
                                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                                            <span className={cn(
                                                "text-4xl font-black tracking-tighter",
                                                stats?.risk_score >= 80 ? "text-emerald-600" :
                                                stats?.risk_score >= 50 ? "text-amber-600" : "text-red-600"
                                            )}>
                                                {stats?.risk_score || 0}
                                            </span>
                                            <span className="text-[9px] font-bold uppercase tracking-widest text-slate-400">Risk Score</span>
                                        </div>
                                    </div>
                                    <p className="mt-4 text-xs font-medium text-slate-500 text-center max-w-[200px]">
                                        {stats?.risk_score >= 80 ? "Your security posture is strong. Keep updated." :
                                         stats?.risk_score >= 50 ? "Several vulnerabilities detected. Action recommended." :
                                         "Critical security risks found. Immediate action required."}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Top Prioritized Fixes */}
                        <div className="md:col-span-2 bg-white border border-slate-200 rounded-[24px] p-6 shadow-sm">
                            <div className="flex items-center justify-between mb-6">
                                <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 flex items-center gap-2">
                                    <Sparkles className="w-3 h-3 text-indigo-500" /> AI-Prioritized Fixes
                                </h3>
                                <div className="text-[9px] font-bold bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full border border-indigo-100">
                                    TOP CRITICAL ACTIONS
                                </div>
                            </div>

                            {loadingStats ? (
                                <div className="space-y-3">
                                    {[1, 2].map(i => <div key={i} className="h-16 bg-slate-50 rounded-xl animate-pulse" />)}
                                </div>
                            ) : stats?.top_fixes?.length > 0 ? (
                                <div className="flex flex-col gap-3">
                                    {stats.top_fixes.map((fix, i) => (
                                        <div key={fix.id} className="flex items-start gap-4 p-4 rounded-xl border border-slate-100 hover:border-indigo-200 hover:bg-indigo-50/30 transition-all group">
                                           <div className={cn(
                                               "w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 mt-0.5",
                                               fix.severity === 'High' ? "bg-red-100 text-red-600" :
                                               fix.severity === 'Medium' ? "bg-amber-100 text-amber-600" : "bg-blue-100 text-blue-600"
                                           )}>
                                               {i + 1}
                                           </div>
                                           <div className="flex-1 min-w-0">
                                               <div className="flex items-center justify-between mb-1">
                                                   <h4 className="font-bold text-slate-900 text-sm truncate pr-4 group-hover:text-indigo-700 transition-colors">
                                                       {fix.v_type}
                                                   </h4>
                                                   <span className="text-[10px] font-mono text-slate-400 truncate max-w-[120px]">
                                                       {new URL(fix.affected_url).pathname}
                                                   </span>
                                               </div>
                                               <p className="text-xs text-slate-500 line-clamp-1 mb-2">{fix.remediation_simple || fix.remediation}</p>
                                               <div className="flex items-center gap-3">
                                                   <div className="flex items-center gap-1.5">
                                                       <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
                                                       <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">
                                                           Confidence: {(fix.confidence * 100).toFixed(0)}%
                                                       </span>
                                                   </div>
                                                   {fix.endpoint_sensitivity !== 'public' && (
                                                       <div className="text-[9px] font-bold uppercase tracking-wider text-red-500 bg-red-50 px-1.5 py-0.5 rounded border border-red-100">
                                                           {fix.endpoint_sensitivity} Asset
                                                       </div>
                                                   )}
                                               </div>
                                           </div>
                                           <Button 
                                                variant="ghost" 
                                                size="sm"
                                                className="h-8 w-8 p-0 rounded-full hover:bg-indigo-100 text-slate-400 hover:text-indigo-600"
                                                onClick={() => router.push(`/scan-result?scanId=${recentScans.find(s => s.status === 'Completed')?.id || ''}#fix-${fix.id}`)} // Fallback linking logic
                                            >
                                               <ArrowRight className="w-4 h-4" />
                                           </Button>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center py-8">
                                    <div className="w-12 h-12 bg-emerald-50 rounded-full flex items-center justify-center mx-auto mb-3 text-emerald-500">
                                        <CheckCircle className="w-6 h-6" />
                                    </div>
                                    <p className="text-sm font-bold text-slate-900">All clear!</p>
                                    <p className="text-xs text-slate-500">No high priority fixes needed right now.</p>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Recent Scans Section */}
                    <div className="animate-in fade-in slide-in-from-bottom-4 duration-700 delay-200">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-sm font-bold uppercase tracking-[0.2em] text-slate-400 font-mono flex items-center gap-2">
                                <div className="w-1 h-4 bg-slate-300 rounded-full" />
                                Scan History
                            </h3>
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
                                    onClick={() => router.push('/start-scan')}
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
                                        onClick={() => router.push(`/scan-result?scanId=${scan.id}`)}
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
