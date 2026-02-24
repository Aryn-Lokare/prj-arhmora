"use client";

import { useTheme } from "next-themes";
import { Sun, Moon } from "lucide-react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

export function ThemeToggle({ className }) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Avoid hydration mismatch by waiting until mounted
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className={cn("w-10 h-10", className)} />;
  }

  return (
    <button
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      className={cn(
        "relative w-11 h-11 flex items-center justify-center rounded-xl transition-all duration-300 active:scale-90",
        "bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm",
        "hover:border-blue-500/50 dark:hover:border-blue-400/50",
        className
      )}
      aria-label="Toggle Theme"
    >
      <div className="relative w-5 h-5">
        <Sun 
          className={cn(
            "absolute inset-0 w-full h-full transition-all duration-500 transform",
            theme === "dark" ? "rotate-90 scale-0 opacity-0" : "rotate-0 scale-100 opacity-100 text-amber-500"
          )} 
        />
        <Moon 
          className={cn(
            "absolute inset-0 w-full h-full transition-all duration-500 transform",
            theme === "dark" ? "rotate-0 scale-100 opacity-100 text-blue-400" : "-rotate-90 scale-0 opacity-0"
          )} 
        />
      </div>
    </button>
  );
}
