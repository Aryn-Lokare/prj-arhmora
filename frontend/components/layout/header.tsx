"use client";

import Link from "next/link";
import { Space_Grotesk } from "next/font/google";

const spaceGrotesk = Space_Grotesk({
    subsets: ["latin"],
    weight: ["500"],
    style: ["normal"]
});

export function Header() {
    return (
        <header className="fixed top-0 left-0 right-0 z-50 glass border-b border-border/40">
            <div className="container mx-auto px-4 h-16 flex items-center justify-between">
                <Link href="/" className="group flex items-center gap-2">
                    <div className="w-8 h-8 bg-primary rounded-sm flex items-center justify-center">
                        <span className="text-primary-foreground font-mono font-bold text-lg">A</span>
                    </div>
                    <span
                        className={`${spaceGrotesk.className} text-xl font-bold tracking-tighter text-foreground hover:text-primary transition-colors duration-200`}
                    >
                        arhmora.
                    </span>
                </Link>

                <div className="flex items-center gap-4">
                    <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-muted/30 rounded-full border border-border/50">
                        <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></div>
                        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground font-bold">Secure Connection</span>
                    </div>
                </div>
            </div>
        </header>
    );
}
