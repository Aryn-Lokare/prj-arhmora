"use client";

import { motion, useScroll, useTransform } from "framer-motion";
import { useRef } from "react";
import { 
    Search, 
    ShieldCheck, 
    Zap, 
    ChevronRight,
    Target,
    Activity,
    Layers
} from "lucide-react";

const steps = [
    {
        title: "Surface Mapping",
        description: "Armora extracts parameters and prepares clean injection vectors without scanning static assets or irrelevant endpoints.",
        icon: Target,
        step: "01"
    },
    {
        title: "Exploit Verification",
        description: "Payloads are executed in controlled conditions. Baseline vs injected responses are compared for time, hash, and status changes.",
        icon: Activity,
        step: "02"
    },
    {
        title: "Evidence & Intelligence",
        description: "Confirmed findings are enriched with AI-generated remediation, technical explanation, and business impact — ready for teams and stakeholders.",
        icon: ShieldCheck,
        step: "03"
    }
];

export function LandingHowItWorks() {
    const sectionRef = useRef(null);
    const { scrollYProgress } = useScroll({
        target: sectionRef,
        offset: ["start end", "end start"]
    });

    const scaleX = useTransform(scrollYProgress, [0.2, 0.5], [0, 1]);

    return (
        <section id="how-it-works" ref={sectionRef} className="py-32 px-6 bg-gray-50 overflow-hidden">
            <div className="max-w-7xl mx-auto">
                <div className="text-center mb-24 space-y-4">
                    <motion.h2 
                        initial={{ opacity: 0, scale: 0.9 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        className="text-[13px] font-bold text-[#6C63FF] uppercase tracking-[0.3em] font-mono"
                    >
                        HOW ARMORA WORKS
                    </motion.h2>
                    <motion.h3 
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        className="text-4xl md:text-5xl font-black text-[#131415] uppercase leading-tight font-heading"
                    >
                        Two Layers. <br /> 
                        <span className="text-[#6C63FF] italic">Zero Guesswork.</span>
                    </motion.h3>
                </div>

                <div className="relative">
                    {/* Connecting Line */}
                    <motion.div 
                        style={{ scaleX, originX: 0 }}
                        className="hidden md:block absolute top-[60px] left-[10%] right-[10%] h-[2px] bg-gradient-to-r from-[#6C63FF]/20 via-[#6C63FF] to-[#6C63FF]/20" 
                    />

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-16 relative z-10">
                        {steps.map((step, index) => (
                            <motion.div 
                                key={index}
                                initial={{ opacity: 0, y: 40 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ delay: index * 0.2, duration: 0.8 }}
                                className="flex flex-col items-center text-center space-y-8"
                            >
                                <div className="relative group">
                                    <div className="w-32 h-32 rounded-full bg-white border-4 border-gray-50 flex items-center justify-center relative z-10 transition-transform duration-500 group-hover:scale-110 shadow-sm">
                                        <step.icon className="w-12 h-12 text-[#6C63FF]" />
                                        <div className="absolute -top-2 -right-2 w-10 h-10 rounded-full bg-[#6C63FF] flex items-center justify-center text-white font-black text-xs border-4 border-white">
                                            {step.step}
                                        </div>
                                    </div>
                                    <div className="absolute inset-0 bg-[#6C63FF]/20 blur-3xl rounded-full scale-0 group-hover:scale-100 transition-transform duration-500" />
                                </div>

                                <div className="space-y-4">
                                    <h4 className="text-2xl font-bold text-[#131415] font-heading uppercase tracking-tight">{step.title}</h4>
                                    <p className="text-gray-600 font-medium leading-relaxed font-body max-w-xs mx-auto">
                                        {step.description}
                                    </p>
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </div>
            </div>
        </section>
    );
}
