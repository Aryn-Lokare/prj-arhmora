"use client";

import { useMemo, useEffect, useState } from "react";
import { Shield, Target, CheckCircle, AlertCircle, TrendingUp, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, useSpring, useTransform, animate } from "framer-motion";

const Counter = ({ value }) => {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    const numericValue = typeof value === 'string' ? parseFloat(value) : value;
    const controls = animate(0, numericValue, {
      duration: 2,
      onUpdate: (latest) => setDisplayValue(Math.floor(latest)),
      ease: "easeOut"
    });
    return () => controls.stop();
  }, [value]);

  return <>{displayValue}{typeof value === 'string' && value.includes('%') ? '%' : ''}</>;
};

const StatCard = ({ title, value, trend, percentage, color, icon: Icon, index }) => {
  const radius = 18;
  const circumference = 2 * Math.PI * radius;
  
  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.5 }}
      whileHover={{ y: -5 }}
      className="bg-white p-6 rounded-2xl border border-border premium-shadow transition-all hover:card-shadow group"
    >
      <div className="flex justify-between items-start mb-4">
        <motion.div 
          whileHover={{ rotate: 15 }}
          className={cn("p-2.5 rounded-xl text-white", color)}
        >
          <Icon className="w-5 h-5" />
        </motion.div>
        <div className="flex items-center gap-1 text-xs font-semibold">
           {trend > 0 ? (
             <span className="text-emerald-500 flex items-center">
               <TrendingUp className="w-3 h-3 mr-0.5" /> +{trend}%
             </span>
           ) : (
             <span className="text-rose-500 flex items-center">
               <TrendingDown className="w-3 h-3 mr-0.5" /> {trend}%
             </span>
           )}
        </div>
      </div>
      
      <div className="flex justify-between items-end">
        <div>
          <h3 className="text-2xl font-bold tracking-tight text-foreground">
            <Counter value={value} />
          </h3>
          <p className="text-xs font-semibold text-muted-foreground mt-1">{title}</p>
        </div>
        
        <div className="relative w-12 h-12 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90">
            <circle
              cx="24"
              cy="24"
              r={radius}
              stroke="currentColor"
              strokeWidth="4"
              fill="transparent"
              className="text-slate-100"
            />
            <motion.circle
              cx="24"
              cy="24"
              r={radius}
              stroke="currentColor"
              strokeWidth="4"
              fill="transparent"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset: circumference - (percentage / 100) * circumference }}
              transition={{ duration: 1.5, ease: "easeOut", delay: index * 0.1 + 0.5 }}
              className={cn("progress-ring__circle", color.replace('bg-', 'text-'))}
              strokeLinecap="round"
            />
          </svg>
          <span className="absolute text-[10px] font-bold text-foreground">{percentage}%</span>
        </div>
      </div>
    </motion.div>
  );
};

export function DashboardStats({ stats }) {
  const cards = useMemo(() => [
    {
      title: "Total Scans",
      value: stats?.total_scans || 0,
      trend: 12,
      percentage: 85,
      color: "bg-stat-blue",
      icon: Target,
    },
    {
      title: "Active Vulns",
      value: stats?.vulnerabilities_count || 0,
      trend: -5,
      percentage: 42,
      color: "bg-rose-500",
      icon: AlertCircle,
    },
    {
      title: "Total Fixed",
      value: stats?.fixed_count || 0,
      trend: 8,
      percentage: 76,
      color: "bg-stat-green",
      icon: CheckCircle,
    },
    {
      title: "Security Health",
      value: stats?.risk_score || 0,
      trend: 2,
      percentage: stats?.risk_score || 0,
      color: "bg-stat-orange",
      icon: Shield,
    }
  ], [stats]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {cards.map((card, idx) => (
        <StatCard key={idx} {...card} index={idx} />
      ))}
    </div>
  );
}
