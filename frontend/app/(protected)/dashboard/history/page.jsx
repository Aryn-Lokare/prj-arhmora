// frontend/app/(protected)/dashboard/history/page.jsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { ArrowRight, Clock, Globe, Shield, Filter, Search, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

export default function HistoryPage() {
    const { logout, loading: authLoading } = useAuth();
    const router = useRouter();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState("");

    useEffect(() => {
        fetchScans();
    }, []);

    const fetchScans = async () => {
        try {
            const response = await api.get('/scan/history/');
            if (response.data.success) {
                setScans(response.data.data);
            }
        } catch (error) {
            console.error("Error fetching scan history:", error);
        } finally {
            setLoading(false);
        }
    };

    const handleViewScan = (scanId) => {
        router.push(`/scan-result?scanId=${scanId}`);
    };

    const filteredScans = scans.filter(scan =>
        scan.target_url.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (authLoading) {
        return <PageLoader text="Loading Cloud Archive..." />;
    }

    return (
        <div className="flex flex-col min-h-screen bg-[#FDFBFB]">
            <DashHeader />

            <main className="flex-1 pt-32 pb-24">
                <div className="max-w-[1000px] mx-auto px-6">
                    {/* Header Section */}
                    <div className="flex flex-col md:flex-row md:items-end justify-between mb-10 gap-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
                        <div>
                            <div className="flex items-center gap-2 mb-2 text-blue-600">
                                <Shield className="w-4 h-4" />
                                <span className="text-[10px] font-black uppercase tracking-[0.2em]">Scan Archive</span>
                            </div>
                            <h1 className="text-3xl font-bold tracking-tight text-slate-900">Historical Assessments</h1>
                            <p className="text-slate-500 font-medium text-sm mt-1">Manage and review your organization's security posture.</p>
                        </div>

                        <div className="flex items-center gap-3">
                            <div className="relative group">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-blue-500 transition-colors" />
                                <input
                                    type="text"
                                    placeholder="Search target URL..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="bg-white border border-slate-200 rounded-xl pl-10 pr-4 py-2 text-sm font-medium w-full md:w-64 focus:outline-none focus:ring-4 focus:ring-blue-500/5 focus:border-blue-500 transition-all shadow-sm"
                                />
                            </div>
                            <Button variant="outline" className="rounded-xl border-slate-200 text-slate-600 font-bold px-4 h-10 shadow-sm hover:bg-white hover:border-slate-300">
                                <Filter className="w-4 h-4 mr-2 opacity-60" /> Filter
                            </Button>
                        </div>
                    </div>

                    {/* Content Section */}
                    {loading ? (
                        <div className="grid grid-cols-1 gap-4">
                            {[1, 2, 3, 4, 5].map(i => (
                                <div key={i} className="h-24 bg-slate-50 rounded-2xl animate-pulse" />
                            ))}
                        </div>
                    ) : filteredScans.length === 0 ? (
                        <div className="bg-white border-2 border-dashed border-slate-200 rounded-[32px] p-24 text-center animate-in fade-in zoom-in-95 duration-500">
                            <div className="w-20 h-20 bg-slate-50 rounded-3xl flex items-center justify-center mb-6 mx-auto border border-slate-100">
                                <Globe className="w-10 h-10 text-slate-300" />
                            </div>
                            <h3 className="text-xl font-bold text-slate-900 mb-2">No records found</h3>
                            <p className="text-slate-500 font-medium mb-8 max-w-xs mx-auto text-sm">We couldn't find any security scans matching your criteria.</p>
                            <Button
                                onClick={() => router.push("/start-scan")}
                                className="bg-blue-600 hover:bg-blue-700 rounded-xl font-bold px-8 h-12 shadow-lg shadow-blue-500/10"
                            >
                                Launch First Scan
                            </Button>
                        </div>
                    ) : (
                        <div className="bg-white border border-slate-200/60 rounded-[32px] overflow-hidden shadow-xl shadow-slate-200/30 animate-in fade-in slide-in-from-bottom-4 duration-700">
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50/50 border-b border-slate-100">
                                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Target Infrastructure</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Status</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Timestamp</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Findings</th>
                                            <th className="px-6 py-4"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100">
                                        {filteredScans.map((scan) => (
                                            <tr
                                                key={scan.id}
                                                onClick={() => handleViewScan(scan.id)}
                                                className="group hover:bg-blue-50/30 transition-colors cursor-pointer"
                                            >
                                                <td className="px-6 py-6">
                                                    <div className="flex items-center gap-4">
                                                        <div className="w-10 h-10 bg-slate-50 rounded-xl flex items-center justify-center text-slate-400 border border-slate-100 group-hover:bg-white group-hover:border-blue-200 group-hover:text-blue-500 transition-all">
                                                            <Globe className="w-5 h-5" />
                                                        </div>
                                                        <span className="font-bold text-slate-900 group-hover:text-blue-700 transition-colors truncate max-w-[200px]">
                                                            {scan.target_url}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6">
                                                    <div className={cn(
                                                        "inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border shadow-sm",
                                                        scan.status === 'Completed' ? "bg-emerald-50 text-emerald-600 border-emerald-100" :
                                                            scan.status === 'Pending' ? "bg-blue-50 text-blue-600 border-blue-100" : "bg-red-50 text-red-600 border-red-100"
                                                    )}>
                                                        <div className={cn("w-1.5 h-1.5 rounded-full shadow-sm",
                                                            scan.status === 'Completed' ? "bg-emerald-500" :
                                                                scan.status === 'Pending' ? "bg-blue-500 animate-pulse" : "bg-red-500"
                                                        )} />
                                                        {scan.status}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6">
                                                    <div className="flex flex-col">
                                                        <span className="text-sm font-bold text-slate-900">{new Date(scan.timestamp).toLocaleDateString()}</span>
                                                        <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">{new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6">
                                                    <div className="flex items-center gap-1">
                                                        <span className={cn(
                                                            "text-[13px] font-black",
                                                            (scan.findings?.length || 0) > 0 ? "text-slate-900" : "text-slate-300"
                                                        )}>
                                                            {scan.findings?.length || 0}
                                                        </span>
                                                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Vulns</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6 text-right">
                                                    <div className="flex items-center justify-end gap-2">
                                                        <button className="p-2 rounded-lg text-slate-300 hover:bg-white hover:text-slate-900 transition-all opacity-0 group-hover:opacity-100">
                                                            <MoreHorizontal className="w-5 h-5" />
                                                        </button>
                                                        <div className="w-8 h-8 rounded-full bg-transparent flex items-center justify-center text-slate-300 group-hover:bg-blue-600 group-hover:text-white transition-all transform group-hover:rotate-[-45deg]">
                                                            <ArrowRight className="w-5 h-5" />
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    <div className="mt-12 flex items-center justify-between text-[11px] font-bold text-slate-400 uppercase tracking-[0.3em] px-2 opacity-50">
                        <span>Organization Index: ARH-1029</span>
                        <span>Total Scans: {scans.length}</span>
                    </div>
                </div>
            </main >
        </div >
    );
}
