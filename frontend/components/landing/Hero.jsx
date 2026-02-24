"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export function LandingHero() {
    return (
        <section className="relative min-h-screen flex flex-col items-center pt-32 pb-20 overflow-hidden bg-white">
            {/* Grid Background */}
            <div className="absolute inset-0 z-0 text-gray-200">
                <div 
                    className="absolute inset-0" 
                    style={{
                        backgroundImage: `linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)`,
                        backgroundSize: '4rem 4rem',
                        maskImage: 'radial-gradient(ellipse 60% 50% at 50% 0%, black 70%, transparent 100%)',
                        WebkitMaskImage: 'radial-gradient(ellipse 60% 50% at 50% 0%, black 70%, transparent 100%)'
                    }}
                />
                
                {/* Soft Top Radial Glow */}
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[600px] bg-blue-50/30 blur-[120px] rounded-full -z-10" />
            </div>

            {/* Bottom Gradient Overlay (The colorful blur at the bottom) */}
            <div className="absolute bottom-0 left-0 w-full h-[500px] pointer-events-none z-10 overflow-hidden">
                <div className="absolute -bottom-20 -left-20 w-[600px] h-[400px] bg-pink-300/30 blur-[100px] rounded-full rotate-12" />
                <div className="absolute -bottom-10 left-1/4 w-[500px] h-[350px] bg-purple-300/20 blur-[90px] rounded-full -rotate-12" />
                <div className="absolute -bottom-20 right-0 w-[700px] h-[450px] bg-blue-300/30 blur-[110px] rounded-full" />
            </div>

            <div className="container mx-auto px-6 relative z-20 flex flex-col items-center text-center">
                <motion.h1 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="text-5xl md:text-7xl lg:text-8xl font-bold tracking-tight text-[#131415] leading-[1.1] font-heading max-w-4xl"
                >
                    Exploit-Verified <br />
                    Security Intelligence.
                </motion.h1>

                <motion.p 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 0.1 }}
                    className="mt-8 text-lg md:text-xl text-gray-500 max-w-3xl leading-relaxed"
                >
                    Armora detects real, reproducible vulnerabilities — not probabilities. <br className="hidden md:block" />
                    Every finding is validated through active exploit testing before it reaches your dashboard.
                </motion.p>

                <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 0.2 }}
                    className="mt-10 flex flex-col sm:flex-row items-center gap-6"
                >
                    <Link href="/signup">
                        <Button size="lg" className="h-14 px-10 bg-[#131415] hover:bg-black text-white font-semibold text-lg rounded-full transition-all shadow-xl shadow-black/10">
                            Start Verified Scan
                        </Button>
                    </Link>
                    <Link href="#how-it-works" className="text-[#131415] font-bold hover:underline flex items-center gap-1">
                        See How It Works →
                    </Link>
                </motion.div>

                {/* Dashboard Visualization */}
                <motion.div 
                    initial={{ opacity: 0, y: 40 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 1, delay: 0.4 }}
                    className="mt-20 relative w-full max-w-5xl group"
                >
                    {/* Main Mockup Card */}
                    <div className="relative bg-white rounded-2xl border border-gray-100 shadow-2xl shadow-blue-500/5 overflow-hidden p-1">
                        <div className="bg-white p-8 md:p-12 space-y-8">
                            <div className="flex items-center justify-between border-b border-gray-50 pb-6">
                                <span className="text-xl font-bold text-[#131415]">Threat Detection Analysis</span>
                                <div className="flex gap-6 text-sm font-medium text-gray-400">
                                    <span className="flex items-center gap-2 font-mono"><div className="w-4 h-4 rounded-full border border-gray-200 flex items-center justify-center text-[10px]">✓</div> 0.07% False Pos</span>
                                    <span className="flex items-center gap-2">Security ID</span>
                                </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-12 text-left">
                                <div className="space-y-4">
                                    <span className="text-xs uppercase tracking-widest text-gray-400 font-bold">Vulnerability Score</span>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="bg-gray-50/50 p-6 rounded-xl space-y-2">
                                            <div className="text-2xl font-bold text-red-500 font-mono">77.65</div>
                                        </div>
                                        <div className="bg-gray-50/50 p-6 rounded-xl space-y-2">
                                            <div className="text-xs text-gray-400 font-mono">Risk Level</div>
                                            <div className="text-xl font-bold text-orange-500 font-mono">Critical</div>
                                        </div>
                                    </div>
                                </div>
                                <div className="space-y-4">
                                    <span className="text-xs uppercase tracking-widest text-gray-400 font-bold">Active Exploits</span>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="bg-gray-50/50 p-6 rounded-xl space-y-2">
                                            <div className="text-2xl font-bold text-[#131415] font-mono">31</div>
                                        </div>
                                        <div className="bg-gray-50/50 p-6 rounded-xl space-y-2">
                                            <div className="text-2xl font-bold text-[#131415] font-mono">25</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Floating Badges */}
                    <motion.div 
                        animate={{ y: [0, -10, 0] }}
                        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                        className="absolute -top-10 -right-10 md:right-0 bg-white p-4 rounded-2xl shadow-2xl border border-gray-50 flex items-center gap-4 z-30"
                    >
                        <div className="w-10 h-10 rounded-full bg-[#6C63FF] flex items-center justify-center text-white">
                            <span className="text-lg">🛡</span>
                        </div>
                        <div className="text-left">
                            <div className="text-sm font-bold text-[#131415]">AI Patch Analysis</div>
                            <div className="text-xs text-gray-400">by arhmora ai</div>
                        </div>
                    </motion.div>

                    <motion.div 
                        animate={{ y: [0, 10, 0] }}
                        transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
                        className="absolute -bottom-10 -left-10 md:left-10 bg-white p-4 rounded-2xl shadow-2xl border border-gray-50 flex items-center gap-3 z-30 max-w-[200px]"
                    >
                        <div className="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-green-500 text-sm">
                            ✓
                        </div>
                        <div className="text-left">
                            <div className="text-[10px] font-medium text-gray-500 leading-tight">Perimeter Secure, No anomalies detected in last 24h.</div>
                        </div>
                    </motion.div>
                </motion.div>
            </div>
        </section>
    );
}
