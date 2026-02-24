"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import Image from "next/image";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";

export function LandingNavbar() {
    const [isScrolled, setIsScrolled] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 20);
        };
        window.addEventListener("scroll", handleScroll);
        return () => window.removeEventListener("scroll", handleScroll);
    }, []);

    const navLinks = [
        { name: "Features", href: "#features" },
        { name: "How It Works", href: "#how-it-works" }
    ];

    return (
        <motion.nav 
            initial={{ y: -100 }}
            animate={{ y: 0 }}
            transition={{ duration: 0.5, ease: "easeOut" }}
            className={`fixed top-0 left-0 w-full h-20 z-50 px-6 md:px-12 flex items-center justify-between transition-all duration-300 ${
                isScrolled ? "bg-white/80 backdrop-blur-lg border-b border-gray-100 shadow-sm" : "bg-transparent"
            }`}
        >
            <div className="flex items-center gap-10">
                <Link href="/" className="flex items-center gap-3 group">
                    <Image 
                        src="/Group 17.png" 
                        alt="Arhmora" 
                        width={200} 
                        height={52} 
                        className="h-12 w-auto object-contain"
                    />
                    <span className="text-2xl font-bold tracking-tighter text-[#131415] font-space lowercase mt-1">
                        arhmora
                    </span>
                </Link>
                
                <div className="hidden lg:flex items-center gap-6">
                    {navLinks.map((link) => (
                        <Link 
                            key={link.name} 
                            href={link.href} 
                            className="text-sm font-medium text-gray-500 hover:text-black transition-colors"
                        >
                            {link.name}
                        </Link>
                    ))}
                </div>
            </div>

            <div className="flex items-center gap-3">
                <Link href="/login">
                    <Button variant="ghost" className="text-sm font-semibold text-gray-700 hover:text-black hover:bg-transparent">
                        Sign In
                    </Button>
                </Link>
                <Link href="/signup">
                    <Button className="h-10 px-6 bg-[#131415] hover:bg-black text-white font-semibold rounded-full border-none transition-all active:scale-[0.98]">
                        Start Scanning
                    </Button>
                </Link>
            </div>
        </motion.nav>
    );
}
