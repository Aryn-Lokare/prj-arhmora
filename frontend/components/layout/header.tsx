"use client";

import Link from "next/link";
import { Space_Grotesk } from "next/font/google";
import { usePathname } from "next/navigation";

const spaceGrotesk = Space_Grotesk({
    subsets: ["latin"],
    weight: ["500"],
    style: ["normal"]
});

export function Header() {
    const pathname = usePathname();
    if (pathname.startsWith("/dashboard")) return null;

    return (
        <header className="fixed top-0 left-0 right-0 z-50 glass border-b border-border/40">
            <div className="container mx-auto px-4 h-16 flex items-center justify-between">
                <Link href="/" className="group flex items-center gap-2">

                    <span
                        className={`${spaceGrotesk.className} text-xl font-bold tracking-tighter text-foreground hover:text-primary transition-colors duration-200`}
                    >
                        arhmora.
                    </span>
                </Link>
            </div>
        </header>
    );
}
