import { cn } from "@/lib/utils";

export function TechLoader({ className, size = "md", text }) {
    const sizeClasses = {
        sm: "w-8 h-8",
        md: "w-12 h-12",
        lg: "w-16 h-16",
        xl: "w-24 h-24"
    };

    return (
        <div className={cn("flex flex-col items-center gap-4", className)}>
            <div className={cn("relative flex items-center justify-center", sizeClasses[size])}>
                {/* Outer Ring */}
                <div className="absolute inset-0 border-4 border-slate-100 rounded-full"></div>

                {/* Spinning Gradient Ring */}
                <div className="absolute inset-0 border-4 border-transparent border-t-blue-500 border-r-blue-300 rounded-full animate-spin [animation-duration:1.5s]"></div>

                {/* Inner Opposite Ring */}
                <div className="absolute inset-2 border-4 border-transparent border-b-indigo-400 border-l-indigo-200 rounded-full animate-spin [animation-duration:2s] [animation-direction:reverse]"></div>

                {/* Core Pulse */}
                <div className="w-1/3 h-1/3 bg-blue-500/20 rounded-full animate-pulse flex items-center justify-center">
                    <div className="w-1.5 h-1.5 bg-blue-600 rounded-full shadow-[0_0_8px_2px_rgba(37,99,235,0.5)]"></div>
                </div>
            </div>
            {text && (
                <p className="text-sm font-bold text-slate-400 uppercase tracking-widest font-mono animate-pulse">
                    {text}
                </p>
            )}
        </div>
    );
}

export function PageLoader({ text = "Initializing Core..." }) {
    return (
        <div className="min-h-screen flex items-center justify-center bg-[#FDFBFB]">
            <TechLoader size="xl" text={text} />
        </div>
    );
}
