// frontend/app/(auth)/signup/page.jsx

import { SignupForm } from "@/components/auth/signup-form";
import Image from "next/image";
import Link from "next/link";

export const metadata = {
    title: "Sign Up | Arhmora",
    description: "Create a new account",
};

export default function SignupPage() {
    return (
        <div className="min-h-screen w-full flex flex-col bg-[#f2f4f7] dark:bg-[#0a0a0b] transition-colors duration-300">
            {/* Minimal Navbar */}
            <nav className="w-full px-8 py-6 flex justify-start">
                <Link href="/" className="flex items-center gap-3">
                    <Image 
                        src="/Group 17.png" 
                        alt="Arhmora" 
                        width={180} 
                        height={50} 
                        className="h-11 w-auto object-contain"
                    />
                    <span className="text-xl font-bold tracking-tighter text-[#131415] dark:text-white font-space lowercase mt-1">
                        arhmora
                    </span>
                </Link>
            </nav>

            {/* Centered Signup Form */}
            <main className="flex-1 flex items-center justify-center p-4 -mt-12">
                <SignupForm />
            </main>
        </div>
    );
}
