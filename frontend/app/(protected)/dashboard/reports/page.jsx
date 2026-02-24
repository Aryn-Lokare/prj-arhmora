// frontend/app/(protected)/dashboard/reports/page.jsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { PageLoader } from "@/components/ui/loader";
import { Button } from "@/components/ui/button";
import { Sidebar } from "@/components/layout/sidebar";
import { 
  FileText, 
  Download, 
  Search, 
  Filter, 
  ArrowRight,
  Globe,
  Clock,
  MoreHorizontal
} from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

export default function ReportsPage() {
    const { loading: authLoading } = useAuth();
    const router = useRouter();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState("");

    useEffect(() => {
        fetchReports();
    }, []);

    const fetchReports = async () => {
        try {
            const response = await api.get('/scan/history/');
            if (response.data.success) {
                // Filter for scans that have findings or are completed
                const completedScans = response.data.data.filter(s => s.status === 'Completed');
                setScans(completedScans);
            }
        } catch (error) {
            console.error("Error fetching reports:", error);
        } finally {
            setLoading(false);
        }
    };

    const handleDownloadPDF = async (scanId) => {
        try {
            const response = await api.get(`/scan/${scanId}/download/`, {
                responseType: 'blob'
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `Arhmora_Security_Report_${scanId}.pdf`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (error) {
            console.error("Error downloading PDF:", error);
        }
    };

    const filteredReports = scans.filter(scan =>
        scan.target_url.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (authLoading) {
        return <PageLoader text="Accessing Secure Vault..." />;
    }

    return (
        <div className="flex min-h-screen bg-[#f2f4f7] dark:bg-[#0a0a0b] font-sans transition-colors duration-300">
            <Sidebar />

            <main className="flex-1 ml-[240px] p-8 overflow-y-auto">
                <div className="max-w-5xl mx-auto flex flex-col gap-8">
                    
                    {/* Header Section */}
                    <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
                        <div className="flex flex-col gap-2">
                            <div className="flex items-center gap-2 text-[#1153ed] dark:text-blue-400 font-black uppercase tracking-[0.2em] text-[10px]">
                                <FileText className="w-4 h-4" />
                                Logic Report Archive
                            </div>
                            <h1 className="text-[40px] font-bold text-[#131415] dark:text-white tracking-tight leading-none">
                                Generated Reports
                            </h1>
                            <p className="text-[#767a8c] dark:text-[#94a3b8] font-medium text-sm mt-1">Review and export detailed security intelligence from your assets.</p>
                        </div>

                        <div className="flex items-center gap-3">
                            <div className="relative group">
                                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[#767a8c] dark:text-[#64748b] group-focus-within:text-[#1153ed] dark:group-focus-within:text-blue-400 transition-colors duration-200" />
                                <input
                                    type="text"
                                    placeholder="Filter by target..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-xl pl-11 pr-4 py-2 text-sm font-bold w-full md:w-64 focus:outline-none focus:ring-4 focus:ring-[#1153ed]/5 dark:focus:ring-blue-500/10 focus:border-[#1153ed] dark:focus:border-blue-400 transition-all duration-200 soft-shadow h-11 dark:text-white"
                                />
                            </div>
                            <Button variant="outline" className="rounded-xl border-[#eaecf0] dark:border-[#2a2b2c] bg-white dark:bg-[#131415] text-[#767a8c] dark:text-[#94a3b8] font-black uppercase text-[9px] tracking-widest px-4 h-11 soft-shadow hover:bg-[#f9fafb] dark:hover:bg-[#1e293b] transition-all active:scale-95">
                                <Filter className="w-4 h-4 mr-2" /> Filter
                            </Button>
                        </div>
                    </div>

                    {/* Content Section */}
                    {loading ? (
                        <div className="grid grid-cols-1 gap-4">
                            {[1, 2, 3, 4].map(i => (
                                <div key={i} className="h-24 bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[24px] animate-pulse" />
                            ))}
                        </div>
                    ) : filteredReports.length === 0 ? (
                        <div className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[32px] p-24 text-center soft-shadow animate-in fade-in zoom-in-95 duration-500">
                            <div className="w-20 h-20 bg-[#f2f4f7] dark:bg-[#1e293b] rounded-3xl flex items-center justify-center mb-6 mx-auto border border-[#eaecf0] dark:border-[#2a2b2c]">
                                <FileText className="w-10 h-10 text-[#767a8c] dark:text-[#94a3b8]" />
                            </div>
                            <h3 className="text-xl font-bold text-[#131415] dark:text-white mb-2">Archive Empty</h3>
                            <p className="text-[#767a8c] dark:text-[#94a3b8] font-medium mb-8 max-w-xs mx-auto text-sm">No security reports have been compiled yet. Start a scan to generate one.</p>
                            <Button
                                onClick={() => router.push("/start-scan")}
                                className="bg-[#131415] dark:bg-white dark:text-[#131415] hover:bg-black dark:hover:bg-slate-100 text-white rounded-xl font-bold px-8 h-12 shadow-xl shadow-slate-900/10 active:scale-95 transition-all"
                            >
                                Trigger Neural Scan
                            </Button>
                        </div>
                    ) : (
                        <div className="bg-white dark:bg-[#131415] border border-[#eaecf0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden soft-shadow transition-all animate-in fade-in slide-in-from-bottom-4 duration-700">
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-[#f9fafb] dark:bg-[#1e293b]/50 border-b border-[#f2f4f7] dark:border-[#2a2b2c]">
                                            <th className="px-8 py-5 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Target Infrastructure</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Timestamp</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Format</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-[0.2em]">Findings</th>
                                            <th className="px-8 py-5"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-[#f2f4f7] dark:divide-[#2a2b2c]">
                                        {filteredReports.map((scan) => (
                                            <tr
                                                key={scan.id}
                                                className="group hover:bg-[#1153ed]/[0.02] dark:hover:bg-blue-400/[0.02] transition-colors"
                                            >
                                                <td className="px-8 py-7">
                                                    <div className="flex items-center gap-5">
                                                        <div className="w-11 h-11 bg-[#f2f4f7] dark:bg-[#1e293b] rounded-xl flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] border border-[#eaecf0] dark:border-[#2a2b2c] group-hover:bg-white dark:group-hover:bg-slate-800 group-hover:border-[#1153ed]/20 dark:group-hover:border-blue-400/20 group-hover:text-[#1153ed] dark:group-hover:text-blue-400 transition-all">
                                                            <Globe className="w-5 h-5" />
                                                        </div>
                                                        <div className="flex flex-col">
                                                            <span className="font-bold text-[#131415] dark:text-white group-hover:text-[#1153ed] dark:group-hover:text-blue-400 transition-colors truncate max-w-[200px]">
                                                                {scan.target_url}
                                                            </span>
                                                            <span className="text-[10px] font-bold text-[#767a8c] dark:text-[#94a3b8] uppercase tracking-widest mt-0.5">Report ID: {String(scan.id).slice(0, 8)}</span>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="px-8 py-7">
                                                    <div className="flex flex-col">
                                                        <span className="text-sm font-bold text-[#131415] dark:text-white">{new Date(scan.timestamp).toLocaleDateString()}</span>
                                                        <span className="text-[10px] text-[#767a8c] dark:text-[#64748b] font-black uppercase tracking-wider mt-0.5">{new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                                    </div>
                                                </td>
                                                <td className="px-8 py-7">
                                                     <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest bg-white dark:bg-[#1e293b] border border-[#eaecf0] dark:border-[#334155] shadow-sm text-[#131415] dark:text-white">
                                                        PDF
                                                    </div>
                                                </td>
                                                <td className="px-8 py-7">
                                                    <div className="flex items-center gap-1.5">
                                                        <span className={cn(
                                                            "text-[13px] font-black",
                                                            (scan.findings?.length || 0) > 0 ? "text-[#131415] dark:text-white" : "text-[#767a8c] dark:text-[#64748b] opacity-30"
                                                        )}>
                                                            {scan.findings?.length || 0}
                                                        </span>
                                                        <span className="text-[10px] font-bold text-[#767a8c] dark:text-[#64748b] uppercase tracking-widest">Points</span>
                                                    </div>
                                                </td>
                                                <td className="px-8 py-7 text-right">
                                                    <div className="flex items-center justify-end gap-3">
                                                        <Button 
                                                            onClick={() => handleDownloadPDF(scan.id)}
                                                            className="bg-[#1153ed] hover:bg-[#0041d6] dark:bg-blue-600 dark:hover:bg-blue-700 text-white px-5 rounded-xl font-bold shadow-lg shadow-blue-500/20 dark:shadow-blue-900/40 flex items-center gap-2 transition-all active:scale-95 h-10 text-[11px] font-black uppercase tracking-wider"
                                                        >
                                                            <Download className="w-4 h-4" />
                                                            Export
                                                        </Button>
                                                        <button 
                                                            onClick={() => router.push(`/scan-result?scanId=${scan.id}`)}
                                                            className="w-10 h-10 rounded-xl bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center text-[#767a8c] dark:text-[#94a3b8] hover:bg-[#131415] dark:hover:bg-white hover:text-white dark:hover:text-[#131415] transition-all transform hover:rotate-[-45deg] active:scale-90 border border-transparent dark:border-[#2a2b2c]"
                                                        >
                                                            <ArrowRight className="w-5 h-5" />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    <div className="mt-8 flex items-center justify-between text-[10px] font-black text-[#767a8c] dark:text-[#64748b] uppercase tracking-[0.4em] px-4 opacity-40">
                        <span>Vault Index: RPT-LOGS</span>
                        <span>Total Reports: {scans.length}</span>
                    </div>
                </div>
            </main >
        </div >
    );
}
