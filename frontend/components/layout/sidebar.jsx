// frontend/components/layout/sidebar.jsx

"use client";

import { useState } from "react";
import Image from "next/image";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { LayoutDashboard, History, Settings, FileText, LogOut, User } from "lucide-react";
import { cn } from "@/lib/utils";

export function Sidebar() {
    const { logout, user } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    const navItems = [
        { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
        { label: "Scans", href: "/dashboard/history", icon: History },
        { label: "Reports", href: "#", icon: FileText },
        { label: "Settings", href: "#", icon: Settings },
    ];

    return (
        <aside className="fixed left-0 top-0 bottom-0 w-60 bg-white border-r border-[#E2E8F0] flex flex-col">
            {/* Logo Section */}
            <div className="p-6 border-b border-[#E2E8F0]">
                <div 
                    className="flex items-center gap-2 cursor-pointer"
                    onClick={() => router.push("/dashboard")}
                >
                    <Image
                        src="/logo.png"
                        alt="Arhmora Logo"
                        width={32}
                        height={32}
                        className="w-8 h-8 object-contain"
                    />
                    <span 
                        className="text-xl font-bold tracking-tight text-[#0F172A]"
                        style={{ fontFamily: 'var(--font-source-sans), sans-serif' }}
                    >
                        Arhmora
                    </span>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4">
                <div className="space-y-1">
                    {navItems.map((item) => {
                        const isActive = pathname === item.href;
                        return (
                            <button
                                key={item.label}
                                onClick={() => router.push(item.href)}
                                className={cn(
                                    "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200",
                                    isActive
                                        ? "bg-[#2D5BFF] text-white"
                                        : "text-[#64748B] hover:bg-[#F1F5F9] hover:text-[#0F172A]"
                                )}
                            >
                                <item.icon className={cn("w-5 h-5", isActive ? "text-white" : "text-[#64748B]")} />
                                {item.label}
                            </button>
                        );
                    })}
                </div>
            </nav>

            {/* User Profile Section */}
            <div className="p-4 border-t border-[#E2E8F0]">
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-[#F1F5F9] transition-colors duration-200">
                    <div className="w-10 h-10 bg-[#F1F5F9] rounded-full flex items-center justify-center">
                        {user?.profile?.avatar ? (
                            <img 
                                src={user.profile.avatar} 
                                alt="Avatar" 
                                className="w-full h-full rounded-full object-cover" 
                            />
                        ) : (
                            <User className="w-5 h-5 text-[#64748B]" />
                        )}
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-bold text-[#0F172A] truncate">
                            {user?.first_name || 'User'} {user?.last_name || ''}
                        </p>
                        <p className="text-xs text-[#64748B] truncate">
                            {user?.email}
                        </p>
                    </div>
                </div>
                
                <button
                    onClick={logout}
                    className="w-full mt-2 flex items-center gap-3 px-4 py-2 rounded-xl text-sm font-medium text-red-600 hover:bg-red-50 transition-all duration-200"
                >
                    <LogOut className="w-4 h-4" />
                    Log out
                </button>
            </div>
        </aside>
    );
}
