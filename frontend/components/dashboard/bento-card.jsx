// frontend/components/dashboard/bento-card.jsx

"use client";

import { cn } from "@/lib/utils";

export function BentoCard({ children, className, title, subtitle, icon: Icon, badge }) {
  return (
    <div className={cn(
      "bg-white dark:bg-[#131415] rounded-[32px] p-6 border border-[#e2e8f0] dark:border-[#2a2b2c] shadow-sm hover:shadow-md transition-all duration-300 flex flex-col",
      className
    )}>
      {(title || Icon || badge) && (
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            {Icon && (
              <div className="w-10 h-10 rounded-full bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center text-[#1153ed] dark:text-blue-400">
                <Icon size={20} />
              </div>
            )}
            <div>
              {title && <h3 className="text-sm font-bold text-[#131415] dark:text-white tracking-tight">{title}</h3>}
              {subtitle && <p className="text-[11px] font-medium text-[#767a8c] dark:text-[#94a3b8]">{subtitle}</p>}
            </div>
          </div>
          {badge && (
            <span className="px-2.5 py-1 rounded-full bg-[#f2f4f7] dark:bg-[#1e293b] text-[#131415] dark:text-white text-[10px] font-bold uppercase tracking-wider">
              {badge}
            </span>
          )}
        </div>
      )}
      <div className="flex-1">
        {children}
      </div>
    </div>
  );
}
