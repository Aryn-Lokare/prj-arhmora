// frontend/app/(protected)/dashboard/page.jsx

"use client";

import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

export default function DashboardPage() {
    const { user, logout, loading } = useAuth();

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen p-8">
            <div className="max-w-6xl mx-auto space-y-8">
                {/* Header */}
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-border/40 pb-6">
                    <div>
                        <div className="inline-flex items-center gap-2 px-2 py-0.5 bg-primary/10 border border-primary/20 rounded-sm mb-2">
                            <span className="text-[9px] font-mono uppercase tracking-widest text-primary font-bold">Account Protected</span>
                        </div>
                        <h1 className="text-4xl font-black tracking-tighter uppercase">My <span className="text-primary italic">Dashboard</span></h1>
                        <p className="text-muted-foreground font-mono text-[11px] uppercase tracking-wider">Welcome back, {user?.first_name} // Session active</p>
                    </div>
                    <Button variant="outline" onClick={logout} className="rounded-sm font-mono uppercase tracking-widest text-xs h-9 glass">
                        Log Out
                    </Button>
                </div>

                <div className="grid lg:grid-cols-3 gap-8">
                    {/* User Info Card */}
                    <Card className="lg:col-span-2 tech-card overflow-hidden">
                        <div className="bg-primary/5 px-6 py-2 border-b border-border/40 flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold text-muted-foreground">User Profile</span>
                            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"></div>
                        </div>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-xl font-bold tracking-tight uppercase">Personal Details</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-y-6 gap-x-12">
                                <div className="space-y-1">
                                    <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Full Name</p>
                                    <p className="font-bold tracking-tight text-lg">
                                        {user?.first_name} {user?.last_name}
                                    </p>
                                </div>
                                <div className="space-y-1">
                                    <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Email Address</p>
                                    <p className="font-mono text-sm font-bold border-b border-primary/20 inline-block">{user?.email}</p>
                                </div>
                                <div className="space-y-1">
                                    <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Username</p>
                                    <p className="font-bold tracking-tight uppercase">{user?.username}</p>
                                </div>
                                <div className="space-y-1">
                                    <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Joined Date</p>
                                    <p className="font-mono text-sm font-bold">
                                        {new Date(user?.date_joined).toLocaleDateString()}
                                    </p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    {/* Quick Actions */}
                    <div className="space-y-6">
                        <div className="text-[10px] font-mono uppercase tracking-[0.3em] font-black text-primary pl-1">Account Options</div>

                        <Card className="tech-card group cursor-pointer border-l-2 border-l-transparent hover:border-l-primary transition-all">
                            <CardHeader className="p-5">
                                <div className="flex items-center justify-between mb-1">
                                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Edit Profile</CardTitle>
                                    <span className="text-primary opacity-0 group-hover:opacity-100 transition-opacity font-mono text-xs">→</span>
                                </div>
                                <CardDescription className="text-[10px] font-mono uppercase">Change your account details</CardDescription>
                            </CardHeader>
                        </Card>

                        <Card className="tech-card group cursor-pointer border-l-2 border-l-transparent hover:border-l-primary transition-all">
                            <CardHeader className="p-5">
                                <div className="flex items-center justify-between mb-1">
                                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Security Keys</CardTitle>
                                    <span className="text-primary opacity-0 group-hover:opacity-100 transition-opacity font-mono text-xs">→</span>
                                </div>
                                <CardDescription className="text-[10px] font-mono uppercase">Manage your passwords</CardDescription>
                            </CardHeader>
                        </Card>

                        <Card className="tech-card group cursor-pointer border-l-2 border-l-transparent hover:border-l-primary transition-all">
                            <CardHeader className="p-5">
                                <div className="flex items-center justify-between mb-1">
                                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Settings</CardTitle>
                                    <span className="text-primary opacity-0 group-hover:opacity-100 transition-opacity font-mono text-xs">→</span>
                                </div>
                                <CardDescription className="text-[10px] font-mono uppercase">Account preferences</CardDescription>
                            </CardHeader>
                        </Card>
                    </div>
                </div>
            </div>
        </div>
    );
}
