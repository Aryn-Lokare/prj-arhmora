"use client";

import Image from "next/image";
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
                <Link href="/" className="group flex items-center gap-3">
                    <Image
                        src="/Group 17.png"
                        alt="Arhmora Logo"
                        width={200}
                        height={100}
                        className="h-16 w-auto object-contain"
                    />
                    <span className="text-2xl font-bold tracking-tighter text-[#131415] font-space lowercase mt-1">
                        arhmora
                    </span>
                </Link>
            </div>
        </header>
    );
}
