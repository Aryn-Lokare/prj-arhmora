"use client";

import { motion } from "framer-motion";
import { 
    Cpu, 
    Database, 
    Eye, 
    Fingerprint, 
    Globe, 
    Lock, 
    Scan, 
    ShieldAlert 
} from "lucide-react";

const features = [
    {
        title: "Exploit Verification Engine",
        description: "Armora actively tests injection vectors and compares baseline responses to confirm real vulnerabilities — eliminating guesswork and reducing false positives.",
        icon: Cpu,
        color: "#6C63FF"
    },
    {
        title: "Smart Detection Pipeline",
        description: "Each request is analyzed through deterministic response comparison, signature validation, and controlled payload execution.",
        icon: Globe,
        color: "#7D8491"
    },
    {
        title: "Forensic Evidence Vault",
        description: "Every finding includes HTTP request/response snapshots, response deltas, and reproducible payload evidence.",
        icon: Database,
        color: "#6C63FF"
    },
    {
        title: "Parameter Intelligence",
        description: "Automatically extracts GET/POST parameters and identifies injection surfaces without intrusive scanning.",
        icon: Lock,
        color: "#7D8491"
    },
    {
        title: "Verified Triage",
        description: "Confidence is calculated using transparent scoring — exploit success, signature strength, and server behavior.",
        icon: ShieldAlert,
        color: "#6C63FF"
    },
    {
        title: "AI-Powered Explanation",
        description: "Once a vulnerability is confirmed, our AI engine generates executive summaries, remediation guidance, and business impact analysis.",
        icon: Eye,
        color: "#7D8491"
    }
];

const containerVariants = {
    hidden: {},
    visible: {
        transition: {
            staggerChildren: 0.1
        }
    }
};

const itemVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: { 
        opacity: 1, 
        y: 0,
        transition: { duration: 0.6, ease: "easeOut" }
    }
};

export function LandingFeatures() {
    return (
        <section id="features" className="py-32 px-6 bg-white">
            <div className="max-w-7xl mx-auto">
                <div className="mb-20 space-y-4">
                    <motion.h2 
                        initial={{ opacity: 0, x: -20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        className="text-[13px] font-bold text-[#6C63FF] uppercase tracking-[0.3em] font-mono"
                    >
                        CORE ENGINE
                    </motion.h2>
                    <motion.h3 
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: 0.1 }}
                        className="text-4xl md:text-5xl font-black text-[#131415] uppercase leading-tight font-heading"
                    >
                        Built on Proof, <br /> 
                        <span className="text-[#6C63FF] italic">Not Predictions.</span>
                    </motion.h3>
                </div>

                <motion.div 
                    variants={containerVariants}
                    initial="hidden"
                    whileInView="visible"
                    viewport={{ once: true, margin: "-100px" }}
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8"
                >
                    {features.map((feature, index) => (
                        <motion.div 
                            key={index} 
                            variants={itemVariants}
                            whileHover={{ 
                                scale: 1.02, 
                                translateY: -5,
                                boxShadow: "0 20px 40px rgba(0,0,0,0.05), 0 0 20px rgba(108, 99, 255, 0.05)"
                            }}
                            className="p-10 rounded-[20px] bg-gray-50 border border-gray-100 transition-all duration-300 relative group overflow-hidden"
                        >
                            <div className="absolute top-0 right-0 w-32 h-32 bg-[#6C63FF]/5 blur-3xl -mr-16 -mt-16 group-hover:bg-[#6C63FF]/10 transition-colors" />
                            
                            <motion.div 
                                className="w-16 h-16 rounded-2xl bg-white flex items-center justify-center mb-8 border border-gray-100 shadow-inner"
                            >
                                <feature.icon className="w-8 h-8 text-[#6C63FF]" />
                            </motion.div>

                            <h4 className="text-2xl font-bold text-[#131415] mb-4 font-heading">{feature.title}</h4>
                            <p className="text-gray-600 font-medium leading-relaxed font-body">
/
                                {feature.description}
                            </p>
                        </motion.div>
                    ))}
                </motion.div>
            </div>
        </section>
    );
}
