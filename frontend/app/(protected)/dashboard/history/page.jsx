// frontend/app/(protected)/dashboard/history/page.jsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { DashHeader } from "@/components/layout/dash-header";
import { Sidebar } from "@/components/layout/sidebar";
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
        <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans transition-colors duration-300">
            <Sidebar />

            <main className="flex-1 ml-[280px] flex flex-col h-screen pt-20 overflow-y-auto">
                <div className="max-w-[1100px] mx-auto px-6">
                    {/* Header Section */}
                    <div className="flex flex-col md:flex-row md:items-end justify-between mb-10 gap-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
                        <div>
                            <div className="flex items-center gap-2 mb-2 text-[#1153ed] dark:text-blue-400">
                                <Shield className="w-4 h-4" />
                                <span className="text-[10px] font-black uppercase tracking-[0.2em]">Scan Archive</span>
                            </div>
                            <h1 className="text-4xl font-bold tracking-tight text-[#131415] dark:text-white font-heading">Historical Assessments</h1>
                            <p className="text-[#767a8c] dark:text-[#94a3b8] font-medium text-sm mt-1">Manage and review your organization's security posture.</p>
                        </div>

                        <div className="flex items-center gap-3">
                            <div className="relative group">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#767a8c] dark:text-[#94a3b8] group-focus-within:text-[#1153ed] dark:group-focus-within:text-blue-400 transition-colors duration-200" />
                                <input
                                    type="text"
                                    placeholder="Search target URL..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-xl pl-10 pr-4 py-2 text-sm font-medium w-full md:w-64 focus:outline-none focus:ring-4 focus:ring-[#1153ed]/5 focus:border-[#1153ed] dark:focus:border-blue-500 text-[#131415] dark:text-white transition-all duration-200"
                                />
                            </div>
                            <Button variant="outline" className="rounded-xl border-[#eaecf0] dark:border-[#2a2b2c] bg-white dark:bg-[#131415] text-[#767a8c] dark:text-white font-bold px-4 h-10 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors duration-200">
                                <Filter className="w-4 h-4 mr-2 opacity-60" /> Filter
                            </Button>
                        </div>
                    </div>

                    {/* Content Section */}
                    {loading ? (
                        <div className="grid grid-cols-1 gap-4">
                            {[1, 2, 3, 4, 5].map(i => (
                                <div key={i} className="h-24 bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-2xl animate-pulse" />
                            ))}
                        </div>
                    ) : filteredScans.length === 0 ? (
                        <div className="bg-white dark:bg-[#131415] border-2 border-dashed border-[#eaecf0] dark:border-[#2a2b2c] rounded-[32px] p-24 text-center animate-in fade-in zoom-in-95 duration-500">
                            <div className="w-20 h-20 bg-[#f2f4f7] dark:bg-[#1e293b] rounded-3xl flex items-center justify-center mb-6 mx-auto border border-[#eaecf0] dark:border-[#2a2b2c]">
                                <Globe className="w-10 h-10 text-slate-300 dark:text-slate-600" />
                            </div>
                            <h3 className="text-xl font-bold text-[#131415] dark:text-white mb-2">No records found</h3>
                            <p className="text-[#767a8c] dark:text-[#94a3b8] font-medium mb-8 max-w-xs mx-auto text-sm">We couldn't find any security scans matching your criteria.</p>
                            <Button
                                onClick={() => router.push("/start-scan")}
                                className="bg-[#1153ed] hover:bg-blue-600 rounded-xl font-bold px-8 h-12 shadow-lg"
                            >
                                Launch First Scan
                            </Button>
                        </div>
                    ) : (
                        <div className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden shadow-xl shadow-slate-200/20 dark:shadow-none animate-in fade-in slide-in-from-bottom-4 duration-700">
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-[#f9fafb] dark:bg-[#1e293b] border-b border-[#eaecf0] dark:border-[#2a2b2c]">
                                            <th className="px-6 py-4 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Target Infrastructure</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Status</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Timestamp</th>
                                            <th className="px-6 py-4 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Findings</th>
                                            <th className="px-6 py-4"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-[#eaecf0] dark:divide-[#2a2b2c]">
                                        {filteredScans.map((scan) => (
                                            <tr
                                                key={scan.id}
                                                onClick={() => handleViewScan(scan.id)}
                                                className="group hover:bg-blue-50/30 dark:hover:bg-blue-900/10 transition-colors cursor-pointer"
                                            >
                                                <td className="px-6 py-6">
                                                    <div className="flex items-center gap-4">
                                                        <div className="w-10 h-10 bg-[#f2f4f7] dark:bg-[#1e293b] rounded-xl flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] border border-[#eaecf0] dark:border-[#2a2b2c] group-hover:bg-white dark:group-hover:bg-slate-800 group-hover:border-[#1153ed] transition-all">
                                                            <Globe className="w-5 h-5" />
                                                        </div>
                                                        <span className="font-bold text-[#131415] dark:text-white group-hover:text-[#1153ed] dark:group-hover:text-blue-400 transition-colors truncate max-w-[200px]">
                                                            {scan.target_url}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6">
                                                    <div className={cn(
                                                        "inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border shadow-sm",
                                                        scan.status === 'Completed' ? "bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-100 dark:border-emerald-800/30" :
                                                            scan.status === 'Pending' ? "bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border-blue-100 dark:border-blue-800/30" : "bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border-red-100 dark:border-red-800/30"
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
                                                        <span className="text-sm font-bold text-[#131415] dark:text-white">{new Date(scan.timestamp).toLocaleDateString()}</span>
                                                        <span className="text-[11px] text-[#767a8c] dark:text-[#94a3b8] font-bold uppercase tracking-wider">{new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6">
                                                    <div className="flex items-center gap-1">
                                                        <span className={cn(
                                                            "text-[13px] font-black",
                                                            (scan.findings?.length || 0) > 0 ? "text-[#131415] dark:text-white" : "text-[#767a8c] dark:text-[#94a3b8] opacity-30"
                                                        )}>
                                                            {scan.findings?.length || 0}
                                                        </span>
                                                        <span className="text-[10px] font-bold text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest ml-1">Vulns</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-6 text-right">
                                                    <div className="flex items-center justify-end gap-2">
                                                        <button className="p-2 rounded-lg text-[#767a8c] dark:text-[#94a3b8] hover:bg-white dark:hover:bg-slate-800 hover:text-[#131415] dark:hover:text-white transition-all opacity-0 group-hover:opacity-100">
                                                            <MoreHorizontal className="w-5 h-5" />
                                                        </button>
                                                        <div className="w-8 h-8 rounded-full bg-transparent flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] group-hover:bg-[#1153ed] group-hover:text-white transition-all transform group-hover:rotate-[-45deg]">
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

                    <div className="mt-12 flex items-center justify-between text-[11px] font-bold text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.3em] px-2 opacity-50">
                        <span>Organization Index: ARH-1029</span>
                        <span>Total Scans: {scans.length}</span>
                    </div>
                </div>
            </main >
        </div >
    );
}
