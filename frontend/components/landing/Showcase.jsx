"use client";

import { motion } from "framer-motion";
import { Shield, Lock, Terminal, Activity, Eye, Zap } from "lucide-react";

/**
 * Enterprise Showcase Component
 * Features high-fidelity UI mockups with alternating scroll-reveal entrance.
 */

const showcaseItems = [
    {
        title: "Adaptive Dashboard",
        description: "Real-time scan metrics showing Confirmed and Likely findings — no inflated risk scoring.",
        image: "/WhatsApp Image 2026-02-22 at 12.53.16 PM (3).jpeg",
        side: "left"
    },
    {
        title: "Deep Scan View",
        description: "Inspect payload used, response differences, and verification logic behind each detection.",
        image: "/WhatsApp Image 2026-02-22 at 12.53.16 PM (2).jpeg",
        side: "right"
    },
    {
        title: "Hacker's View Section",
        description: "See What Attackers Can Actually Exploit. Not simulated risk. Not anomaly flags. Only vulnerabilities that respond to real exploit attempts.",
        image: "/WhatsApp Image 2026-02-22 at 12.53.16 PM (1).jpeg",
        side: "left"
    },
    {
        title: "Forensic Deep Scan",
        description: "Evidence You Can Reproduce: Payload executed, Baseline vs injected comparison, Server response differences, Attack signature evidence.",
        image: "/WhatsApp Image 2026-02-22 at 12.53.16 PM.jpeg",
        side: "right"
    }
];

const MockupCard = ({ image }) => {
    return (
        <div className="w-full aspect-video bg-white rounded-2xl border border-gray-100 shadow-2xl overflow-hidden relative group">
            <img 
                src={image} 
                alt="Product Screenshot" 
                className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        </div>
    );
};

export function LandingShowcase() {
    return (
        <section id="showcase" className="py-32 px-6 bg-white overflow-hidden">
            <div className="max-w-7xl mx-auto">
                <div className="text-center mb-32 space-y-4">
                    <motion.h2 
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: 1 }}
                        className="text-[13px] font-bold text-[#6C63FF] uppercase tracking-[0.3em] font-mono"
                    >
                        Intelligence Display
                    </motion.h2>
                    <motion.h3 
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        className="text-4xl md:text-5xl font-black text-[#131415] uppercase leading-tight font-heading"
                    >
                        The Power of <br /> 
                        <span className="text-[#6C63FF] italic">Total Visibility.</span>
                    </motion.h3>
                </div>

                <div className="space-y-48">
                    {showcaseItems.map((item, index) => (
                        <div 
                            key={index}
                            className={`flex flex-col lg:flex-row items-center gap-16 lg:gap-24 ${
                                item.side === "right" ? "lg:flex-row-reverse" : ""
                            }`}
                        >
                            {/* Text Content */}
                            <motion.div 
                                initial={{ opacity: 0, x: item.side === "left" ? -50 : 50 }}
                                whileInView={{ opacity: 1, x: 0 }}
                                viewport={{ once: true, margin: "-100px" }}
                                transition={{ duration: 0.8 }}
                                className="lg:w-1/2 space-y-8"
                            >
                                <div className="h-12 w-12 rounded-xl bg-[#6C63FF]/10 flex items-center justify-center">
                                    <Shield size={24} className="text-[#6C63FF]" />
                                </div>
                                <div className="space-y-4">
                                    <h4 className="text-3xl md:text-4xl font-black text-[#131415] font-heading uppercase tracking-tight">
                                        {item.title}
                                    </h4>
                                    <p className="text-gray-600 text-lg md:text-xl leading-relaxed font-body">
/
                                        {item.description}
                                    </p>
                                </div>
                                <motion.button 
                                    whileHover={{ x: 10 }}
                                    className="text-[#6C63FF] font-black text-sm uppercase tracking-widest flex items-center gap-3 group"
                                >
                                    Explore Feature
                                    <div className="w-12 h-[2px] bg-[#6C63FF] transition-all group-hover:w-20" />
                                </motion.button>
                            </motion.div>

                            {/* Mockup Display */}
                            <motion.div 
                                initial={{ opacity: 0, x: item.side === "left" ? 50 : -50, scale: 0.95 }}
                                whileInView={{ opacity: 1, x: 0, scale: 1 }}
                                viewport={{ once: true, margin: "-100px" }}
                                transition={{ duration: 0.8 }}
                                className="lg:w-1/2 w-full relative group"
                            >
                                <div className="absolute -inset-10 bg-[#6C63FF]/10 blur-[120px] rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-1000" />
                                <motion.div 
                                    whileHover={{ scale: 1.02, rotateY: item.side === "left" ? 2 : -2 }}
                                    className="relative z-10 perspective-1000"
                                >
                                <MockupCard image={item.image} />
                                </motion.div>
                            </motion.div>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
