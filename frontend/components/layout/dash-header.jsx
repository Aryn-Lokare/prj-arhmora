// frontend/components/layout/dash-header.jsx

"use client";

import { useState, useRef, useEffect } from "react";
import Image from "next/image";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { Plus, User, LogOut, Settings, LayoutDashboard, History, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

export function DashHeader() {
    const { logout, user } = useAuth();
    const router = useRouter();
    const pathname = usePathname();
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const menuRef = useRef(null);

    const navItems = [
        { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
        { label: "All Scans", href: "/dashboard/history", icon: History },
        { label: "Settings", href: "#", icon: Settings },
    ];

    // Close menu when clicking outside
    useEffect(() => {
        function handleClickOutside(event) {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setIsMenuOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    return (
        <header className="fixed top-2 left-1/2 -translate-x-1/2 w-[95%] max-w-[1200px] h-16 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-800/60 z-50 px-6 rounded-2xl flex items-center justify-between shadow-sm shadow-slate-200/50 dark:shadow-none transition-colors duration-300">
            <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => router.push("/dashboard")}>
                <Image
                     src="/Group 17.png"
                     alt="Arhmora Logo"
                     width={150}
                     height={40}
                     className="h-10 w-auto object-contain"
                />
                <span className="text-xl font-bold tracking-tighter text-slate-900 dark:text-white font-space lowercase mt-1">
                    arhmora
                </span>
            </div>

            <nav className="absolute left-1/2 -translate-x-1/2 hidden md:flex items-center gap-1 bg-slate-100/50 dark:bg-slate-800/50 p-1 rounded-xl border border-slate-200/40 dark:border-slate-700/40">
                {navItems.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <button
                            key={item.label}
                            onClick={() => router.push(item.href)}
                            className={cn(
                                "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200",
                                isActive
                                    ? "bg-white dark:bg-slate-700 text-blue-600 dark:text-blue-400 shadow-sm border border-slate-200/50 dark:border-slate-600/50"
                                    : "text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-white/50 dark:hover:bg-slate-700/50"
                            )}
                        >
                            <item.icon className={cn("w-4 h-4", isActive ? "text-blue-500" : "text-slate-400")} />
                            {item.label}
                        </button>
                    );
                })}
            </nav>

            <div className="flex items-center gap-3">
                <Button
                    variant="outline"
                    size="sm"
                    title="Run active exploit verification against a target URL."
                    onClick={() => {
                        if (pathname === "/dashboard") {
                            document.querySelector('input')?.focus();
                        } else {
                            router.push("/dashboard");
                        }
                    }}
                    className="hidden sm:flex rounded-xl border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-white font-bold h-10 px-4 hover:bg-slate-50 dark:hover:bg-slate-700 hover:border-slate-300 dark:hover:border-slate-600 transition-all active:scale-95"
                >
                    <Plus className="w-4 h-4 mr-2 text-blue-500 stroke-[3px]" />
                    Run Verified Scan
                </Button>

                <div className="h-6 w-px bg-slate-200/60 dark:bg-slate-700 mx-1 hidden sm:block" />

                <div className="relative" ref={menuRef}>
                    <button
                        onClick={() => setIsMenuOpen(!isMenuOpen)}
                        className={cn(
                            "w-10 h-10 rounded-xl bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-800 dark:to-slate-900 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-300 transition-all outline-none active:scale-95",
                            isMenuOpen ? "border-blue-400 dark:border-blue-500 shadow-md shadow-blue-500/10" : "hover:border-slate-300 dark:hover:border-slate-600 hover:shadow-sm"
                        )}
                    >
                        {user?.profile?.avatar ? (
                            <img src={user.profile.avatar} alt="Avatar" className="w-full h-full rounded-xl object-cover" />
                        ) : (
                            <User className="w-5 h-5 text-slate-400 dark:text-slate-500" />
                        )}
                    </button>

                    {isMenuOpen && (
                        <div className="absolute right-0 mt-3 w-56 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl shadow-slate-200/60 dark:shadow-none p-2 z-[60] animate-in fade-in zoom-in-95 duration-200 transform origin-top-right">
                            <div className="px-3 py-2 mb-1">
                                <p className="text-sm font-bold text-slate-900 dark:text-white leading-none mb-1">
                                    {user?.first_name || 'User'} {user?.last_name || ''}
                                </p>
                                <p className="text-[11px] text-slate-500 dark:text-slate-400 font-medium truncate">
                                    {user?.email}
                                </p>
                            </div>

                            <div className="h-px bg-slate-100 dark:bg-slate-800 mx-1 mb-1" />

                            <button className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white transition-colors">
                                <User className="w-4 h-4 opacity-50" /> Profile
                            </button>
                            <button className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white transition-colors">
                                <Settings className="w-4 h-4 opacity-50" /> Settings
                            </button>

                            <div className="h-px bg-slate-100 dark:bg-slate-800 mx-1 my-1" />

                            <button
                                onClick={logout}
                                className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-bold text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 hover:text-red-700 transition-colors"
                            >
                                <LogOut className="w-4 h-4 opacity-70" /> Log out
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
}
