"use client";

import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { ArrowRight, Sparkles } from "lucide-react";
import Link from "next/link";

/**
 * Enterprise Call to Action Section
 * Uses a centered layout with a bold heading and a shimmer-enabled signature button.
 */

export function LandingCTA() {
    return (
        <section className="py-32 px-6 bg-white relative overflow-hidden">
            {/* Ambient Radial Glow */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-[#6C63FF]/10 rounded-full blur-[120px] pointer-events-none" />
            
            <motion.div 
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.8 }}
                className="max-w-4xl mx-auto text-center space-y-10 relative z-10"
            >
                <div className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 border border-gray-200 rounded-full">
                    <Sparkles className="w-4 h-4 text-[#6C63FF]" />
                    <span className="text-[10px] font-bold text-gray-600 uppercase tracking-widest font-mono">Ready for the perimeter?</span>
                </div>

                <h2 className="text-5xl md:text-7xl font-black text-[#131415] uppercase leading-tight font-heading">
                    Stop Guessing. <br />
                    <span className="text-[#6C63FF] italic">Start Verifying.</span>
                </h2>

                <p className="text-xl text-gray-600 max-w-2xl mx-auto font-medium leading-relaxed font-body">
                    Run exploit-verified security scans in under 60 seconds.
                </p>

                <div className="flex flex-col sm:flex-row gap-6 justify-center pt-6">
                    <Link href="/signup">
                        <motion.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            className="relative group overflow-hidden rounded-2xl"
                        >
                            <Button size="lg" className="h-16 px-12 bg-[#6C63FF] hover:bg-[#5a52e6] text-white font-black text-lg rounded-2xl transition-all shadow-xl shadow-[#6C63FF]/30 group relative overflow-hidden">
                                <span className="relative z-10 flex items-center gap-2">
                                    Start Verified Scan →
                                </span>
                                
                                {/* Animated Shimmer Overlay */}
                                <div className="absolute inset-0 w-1/2 h-full bg-white/20 -skew-x-[30deg] -translate-x-full group-hover:translate-x-[200%] transition-transform duration-1000 ease-in-out pointer-events-none" />
                            </Button>
                        </motion.div>
                    </Link>
                </div>

                <div className="pt-12 flex flex-wrap justify-center gap-x-12 gap-y-4">
                    <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-[#7D8491]">
                        <div className="w-1.5 h-1.5 rounded-full bg-[#6C63FF]" />
                        SOC2 Type II Compliant
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-[#7D8491]">
                        <div className="w-1.5 h-1.5 rounded-full bg-[#6C63FF]" />
                        No Credit Card Required
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-[#7D8491]">
                        <div className="w-1.5 h-1.5 rounded-full bg-[#6C63FF]" />
                        GDPR Ready
                    </div>
                </div>
            </motion.div>
        </section>
    );
}
