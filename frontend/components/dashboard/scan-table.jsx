"use client";

import { useState } from "react";
import { Search, ListFilter, Trash2, Edit3, ExternalLink, Globe, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

export function ScanTable({ scans, onRowClick }) {
  const [searchTerm, setSearchTerm] = useState("");

  const filteredScans = scans.filter(scan => 
    scan.target_url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="bg-white rounded-2xl border border-border premium-shadow overflow-hidden">
      {/* Table Header / Actions */}
      <div className="p-5 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
           <div className="flex items-center gap-2 mb-1">
             <h2 className="text-lg font-bold text-foreground">Recent Scans</h2>
             <span className="bg-primary/10 text-primary text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">
               {scans.length} Total
             </span>
           </div>
           <p className="text-xs text-muted-foreground">Keep track of your security assessments and ratings.</p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
            <input 
              type="text" 
              placeholder="Search target URL..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 h-10 w-[240px] bg-secondary border-none rounded-xl text-sm focus:ring-2 focus:ring-primary/20 transition-all outline-none"
            />
          </div>
          <Button variant="outline" className="h-10 rounded-xl border-border bg-white text-muted-foreground font-semibold flex items-center gap-2">
            <ListFilter className="w-4 h-4" />
            Filters
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-secondary/50 border-b border-border">
              <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Target Domain</th>
              <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Health Score</th>
              <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Last Scanned</th>
              <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Status</th>
              <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-muted-foreground text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredScans.map((scan) => {
              const score = scan.risk_score || 0;
              const healthColor = score > 80 ? "bg-emerald-500" : score > 50 ? "bg-amber-500" : "bg-rose-500";
              
              return (
                <tr 
                  key={scan.id} 
                  className="group hover:bg-slate-50/50 cursor-pointer transition-colors"
                  onClick={() => onRowClick(scan.id)}
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-secondary flex items-center justify-center text-primary border border-border group-hover:bg-white transition-colors">
                        <Globe className="w-5 h-5" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-foreground group-hover:text-primary transition-colors">{scan.target_url}</p>
                        <p className="text-[11px] text-muted-foreground font-medium">Neural scan v1.2</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-24 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                        <div 
                          className={cn("h-full rounded-full transition-all duration-1000", healthColor)} 
                          style={{ width: `${score}%` }} 
                        />
                      </div>
                      <span className="text-xs font-bold text-foreground">{score}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <p className="text-xs font-semibold text-foreground">
                      {new Date(scan.timestamp).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
                    </p>
                  </td>
                  <td className="px-6 py-4">
                    <span className={cn(
                      "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border",
                      scan.status === 'Completed' ? "bg-emerald-50 text-emerald-600 border-emerald-100" : 
                      scan.status === 'Pending' ? "bg-blue-50 text-blue-600 border-blue-100 animate-pulse" : 
                      "bg-rose-50 text-rose-600 border-rose-100"
                    )}>
                      <div className={cn("w-1 h-1 rounded-full", scan.status === 'Completed' ? "bg-emerald-500" : scan.status === 'Pending' ? "bg-blue-500" : "bg-rose-500")} />
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                       <Button variant="ghost" size="sm" className="h-8 w-8 p-0 rounded-lg hover:bg-white hover:border-border border border-transparent">
                          <Trash2 className="w-4 h-4 text-muted-foreground hover:text-rose-500" />
                       </Button>
                       <Button variant="ghost" size="sm" className="h-8 w-8 p-0 rounded-lg hover:bg-white hover:border-border border border-transparent">
                          <ExternalLink className="w-4 h-4 text-muted-foreground hover:text-primary" />
                       </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Mockup */}
      <div className="p-4 border-t border-border flex items-center justify-between bg-secondary/30">
        <p className="text-[11px] font-bold text-muted-foreground uppercase tracking-wider">Page 1 of 10</p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="h-8 px-4 rounded-lg text-xs font-bold border-border bg-white" disabled>Previous</Button>
          <Button variant="outline" size="sm" className="h-8 px-4 rounded-lg text-xs font-bold border-border bg-white shadow-sm">Next</Button>
        </div>
      </div>
    </div>
  );
}
