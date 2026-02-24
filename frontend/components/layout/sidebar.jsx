// frontend/components/layout/sidebar.jsx

"use client";

import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import {
  LayoutDashboard,
  ShieldCheck,
  Settings,
  LogOut,
  Plus,
  User,
  FileText,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Image from "next/image";
import Link from "next/link";

export function Sidebar({ showNewScan = true }) {
  const { logout, user } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  const navItems = [
    { label: "Dashboard", sub: "Verified Overview", href: "/dashboard", icon: LayoutDashboard },
    { label: "Scan History", sub: "Exploit Validation Logs", href: "/dashboard/history", icon: ShieldCheck },
    { label: "Report History", sub: "Board-Ready Reports", href: "/dashboard/reports", icon: FileText },
  ];

  const isActive = (path) => pathname === path;

  return (
    <aside className="w-[280px] h-screen bg-white border-r border-[#eaecf0] shadow-sm flex flex-col fixed left-0 top-0 z-50">
      <div className="p-8 pb-4">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <Image 
            src="/Group 17.png" 
            alt="Arhmora" 
            width={180} 
            height={48} 
            className="h-11 w-auto object-contain"
          />
          <span className="text-2xl font-bold tracking-tighter text-[#131415] font-space lowercase mt-1">
            arhmora
          </span>
        </Link>
      </div>

      <nav className="flex-1 px-4 py-8 space-y-1.5">
        <p className="px-4 text-[10px] font-black text-[#98a2b3] uppercase tracking-[0.2em] mb-4 opacity-70">Main Menu</p>
        
        {navItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "flex items-center gap-3.5 px-4 py-3 rounded-xl transition-all duration-300 group relative",
              isActive(item.href)
                ? "bg-[#6C63FF]/5 text-[#6C63FF] shadow-sm border border-[#6C63FF]/10"
                : "text-[#667085] hover:bg-gray-50 hover:text-[#111]"
            )}
          >
            <item.icon className={cn("w-5 h-5", isActive(item.href) ? "text-[#6C63FF]" : "group-hover:text-[#6C63FF]")} />
            <div className="flex flex-col">
              <span className="font-bold text-sm tracking-tight">{item.label}</span>
              <span className="text-[10px] font-medium text-[#767a8c] opacity-60 tracking-tight">{item.sub}</span>
            </div>
          </Link>
        ))}

        {/* CTA Section */}
        {showNewScan && (
          <div className="pt-8 px-2">
            <button
              onClick={() => router.push("/start-scan")}
              title="Run active exploit verification against a target URL."
              className="w-full flex items-center justify-center gap-2 px-4 py-3.5 bg-[#131415] dark:bg-white dark:text-[#131415] text-white rounded-2xl hover:bg-black dark:hover:bg-slate-100 transition-all duration-300 shadow-lg active:scale-[0.98] group"
            >
              <Plus className="w-5 h-5 text-[#1153ed] group-hover:scale-110 transition-transform" />
              <span className="font-bold text-sm">+ Run Verified Scan</span>
            </button>
          </div>
        )}
      </nav>

      {/* User Footer */}
      <div className="p-4 border-t border-[#f2f4f7] mt-auto">
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-3 px-2 py-1">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-slate-50 to-slate-100 border border-[#eaecf0] flex items-center justify-center text-[#767a8c]">
              <User className="w-5 h-5 opacity-60" />
            </div>
            <div className="flex flex-col overflow-hidden">
              <span className="text-sm font-bold text-[#131415] truncate">{user?.first_name || 'Defender'} {user?.last_name || ''}</span>
              <span className="text-[10px] font-medium text-[#767a8c] truncate opacity-70 uppercase tracking-widest">{user?.email?.split('@')[0]}</span>
            </div>
          </div>
          
          <button
            onClick={logout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold text-red-600 hover:bg-red-50 transition-all duration-300 group"
          >
            <LogOut className="w-5 h-5 opacity-70 group-hover:opacity-100" />
            <span>Log out</span>
          </button>
        </div>
      </div>
    </aside>
  );
}
