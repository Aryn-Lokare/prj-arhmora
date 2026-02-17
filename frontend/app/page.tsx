// frontend/app/page.js

import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Decorative pulse element */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] -z-10 animate-pulse"></div>

      <div className="text-center space-y-8 max-w-2xl relative">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-muted/50 border border-border/60 rounded-sm mb-4">
          <span className="w-2 h-2 bg-primary rounded-full animate-ping"></span>
          <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted-foreground font-bold italic">Secure Connection Active</span>
        </div>

        <h1 className="text-6xl font-bold tracking-tight text-foreground leading-[0.9] uppercase font-heading">
          Simple <span className="text-primary italic">Identity</span> <br />
          Protected.
        </h1>

        <p className="text-lg text-muted-foreground max-w-lg mx-auto font-medium leading-relaxed">
          The simple way to secure your digital identity. Modern protection designed for everyone, everywhere.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center pt-8">
          <Link href="/login">
            <Button size="lg" className="rounded-sm px-10 h-14 font-mono uppercase tracking-widest text-xs font-bold transition-all hover:scale-[1.02] active:scale-[0.98]">
              Sign In
            </Button>
          </Link>
          <Link href="/signup">
            <Button size="lg" variant="outline" className="rounded-sm px-10 h-14 font-mono uppercase tracking-widest text-xs font-bold glass transition-all hover:bg-muted/30">
              Get Started
            </Button>
          </Link>
        </div>

        <div className="pt-12 flex items-center justify-center gap-8 opacity-40 grayscale">
          <span className="text-[10px] font-mono tracking-widest uppercase font-bold">Secure</span>
          <span className="text-[10px] font-mono tracking-widest uppercase font-bold">Reliable</span>
          <span className="text-[10px] font-mono tracking-widest uppercase font-bold">Private</span>
        </div>
      </div>
    </div>
  );
}
