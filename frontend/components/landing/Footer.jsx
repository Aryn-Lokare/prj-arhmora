"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import Image from "next/image";
import { Github, Twitter, Linkedin, Mail } from "lucide-react";

/**
 * Enterprise Footer
 * Minimalist design with animated dividers and smooth social icon interaction.
 */

export function LandingFooter() {
    const currentYear = new Date().getFullYear();

    const socialLinks = [
        { icon: Github, href: "#" },
        { icon: Twitter, href: "#" },
        { icon: Linkedin, href: "#" },
        { icon: Mail, href: "#" }
    ];

    return (
        <footer className="bg-gray-50 pt-24 pb-12 px-6 overflow-hidden">
            <div className="max-w-7xl mx-auto space-y-16">
                
                {/* divider line animation */}
                <motion.div 
                    initial={{ scaleX: 0 }}
                    whileInView={{ scaleX: 1 }}
                    viewport={{ once: true }}
                    transition={{ duration: 1.5, ease: "easeInOut" }}
                    className="h-[1px] w-full bg-gradient-to-r from-transparent via-gray-200 to-transparent origin-center"
                />

                <div className="grid grid-cols-1 md:grid-cols-12 gap-12 items-start">
                    {/* Brand Info */}
                    <div className="md:col-span-4 space-y-6">
                        <Link href="/" className="flex items-center gap-3">
                            <Image 
                                src="/Group 17.png" 
                                alt="Arhmora" 
                                width={150} 
                                height={40} 
                                className="h-10 w-auto object-contain"
                            />
                            <span className="text-xl font-bold tracking-tighter text-[#131415] font-space lowercase mt-1">
                                arhmora
                            </span>
                        </Link>
                        <p className="text-[#7D8491] font-medium leading-relaxed max-w-sm font-body">
                            Armora is a verification-first vulnerability detection platform built for engineering teams who value evidence over estimation. <br />
                            Exploit-validated findings. AI-enhanced reporting. Zero noise.
                        </p>
                    </div>

                    {/* Navigation */}
                    <div className="md:col-span-5 grid grid-cols-2 gap-8">
                        <div className="space-y-4">
                            <h5 className="text-[#131415] font-black text-xs uppercase tracking-widest font-mono">Platform</h5>
                            <ul className="space-y-2 text-sm font-medium text-[#7D8491]">
                                <li><Link href="#features" className="hover:text-white transition-colors">Features</Link></li>
                                <li><Link href="#how-it-works" className="hover:text-white transition-colors">Workflow</Link></li>
                                <li><Link href="#showcase" className="hover:text-white transition-colors">Showcase</Link></li>
                            </ul>
                        </div>
                        <div className="space-y-4">
                            <h5 className="text-[#131415] font-black text-xs uppercase tracking-widest font-mono">Company</h5>
                            <ul className="space-y-2 text-sm font-medium text-[#7D8491]">
                                <li><Link href="#" className="hover:text-white transition-colors">Privacy Policy</Link></li>
                                <li><Link href="#" className="hover:text-white transition-colors">Terms of Service</Link></li>
                                <li><Link href="#" className="hover:text-white transition-colors">Contact</Link></li>
                            </ul>
                        </div>
                    </div>

                    {/* Socials */}
                    <div className="md:col-span-3 space-y-6">
                        <h5 className="text-[#131415] font-black text-xs uppercase tracking-widest font-mono">Connect</h5>
                        <div className="flex gap-4">
                            {socialLinks.map((social, index) => (
                                <motion.a 
                                    key={index}
                                    href={social.href}
                                    whileHover={{ y: -5, scale: 1.1 }}
                                    className="w-10 h-10 rounded-xl bg-white border border-gray-100 flex items-center justify-center text-[#7D8491] hover:text-[#6C63FF] hover:border-[#6C63FF]/30 transition-all shadow-sm"
                                >
                                    <social.icon size={18} />
                                </motion.a>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="pt-8 flex flex-col md:flex-row justify-between items-center gap-4 text-[#7D8491] text-[10px] font-bold uppercase tracking-[0.2em] font-mono">
                    <p>© {currentYear} Arhmora Intelligence. All rights reserved.</p>
                    <p>Built with Precision by Aryan</p>
                </div>
            </div>
        </footer>
    );
}
