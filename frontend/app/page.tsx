// frontend/app/page.js

import Link from "next/link";
import { Button } from "@/components/ui/button";

import { LandingNavbar } from "@/components/landing/Navbar";
import { LandingHero } from "@/components/landing/Hero";
import { LandingFeatures } from "@/components/landing/Features";
import { LandingHowItWorks } from "@/components/landing/HowItWorks";
import { LandingShowcase } from "@/components/landing/Showcase";
import { LandingCTA } from "@/components/landing/CTA";
import { LandingFooter } from "@/components/landing/Footer";

export default function HomePage() {
  return (
    <div className="flex flex-col w-full bg-white transition-colors duration-500 overflow-x-hidden">
        <LandingNavbar />
        <main>
            <LandingHero />
            <LandingFeatures />
            <LandingHowItWorks />
            <LandingShowcase />
            <LandingCTA />
        </main>
        <LandingFooter />
    </div>
  );
}
