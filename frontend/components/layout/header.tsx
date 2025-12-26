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
        <header className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border/40">
            <div className="container mx-auto px-4 h-16 flex items-center justify-center">
                <Link href="/" className="group">
                    <span
                        className={`${spaceGrotesk.className} text-2xl font-semibold tracking-tight text-foreground hover:text-primary transition-colors duration-200`}
                    >
                        arhmora
                    </span>
                </Link>
            </div>
        </header>
    );
}
