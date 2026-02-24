"use client";

import { Sparkles, AlertTriangle, ArrowRight, ShoppingCart, ShieldAlert, Cpu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const BundleCard = ({ title, description, items, price, icon: Icon }) => (
  <div className="bg-white rounded-2xl border border-border p-5 mb-6 group hover:card-shadow transition-all">
    <div className="flex items-center gap-3 mb-3">
      <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
        <Icon className="w-5 h-5" />
      </div>
      <h3 className="font-bold text-foreground leading-tight">{title}</h3>
    </div>
    
    <p className="text-[11px] text-muted-foreground mb-4 line-clamp-2">{description}</p>
    
    <div className="space-y-3 mb-5">
      {items.map((item, idx) => (
        <div key={idx} className="flex items-center gap-3">
           <div className="w-8 h-8 rounded-lg bg-secondary flex items-center justify-center overflow-hidden">
             {item.image ? <img src={item.image} className="w-full h-full object-cover" /> : <Cpu className="w-4 h-4 text-muted-foreground" />}
           </div>
           <div>
             <p className="text-[11px] font-bold text-foreground leading-none mb-1">{item.name}</p>
             <p className="text-[10px] text-muted-foreground leading-none">{item.subtext}</p>
           </div>
        </div>
      ))}
    </div>

    <Button className="w-full h-10 bg-white border border-border text-primary font-bold hover:bg-primary hover:text-white hover:premium-shadow transition-all rounded-xl text-xs">
      ${price} - Upgrade Now
    </Button>
  </div>
);

export function AnalyticsPanel({ stats }) {
  return (
    <aside className="w-[320px] hidden xl:flex flex-col border-l border-border bg-white/50 backdrop-blur-md p-6 h-screen sticky top-0 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <h2 className="text-lg font-bold text-foreground">AI Insights</h2>
        <span className="flex items-center gap-1.5 text-[10px] font-bold text-emerald-500 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100">
           <div className="w-1 h-1 bg-emerald-500 rounded-full animate-pulse" />
           LIVE ANALYTICS
        </span>
      </div>

      {/* Critical Alerts Spot */}
      {stats?.top_fixes?.length > 0 && (
        <div className="mb-8 p-4 rounded-2xl bg-rose-50 border border-rose-100 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity">
            <ShieldAlert className="w-12 h-12 text-rose-600" />
          </div>
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-rose-600" />
            <span className="text-[10px] font-bold text-rose-600 uppercase tracking-widest">Immediate Action Required</span>
          </div>
          <p className="text-xs font-bold text-rose-900 mb-1">
            {stats.top_fixes[0].v_type} detected
          </p>
          <p className="text-[10px] text-rose-700/80 mb-3">
            Critical vulnerability found on sensitive endpoint.
          </p>
          <Button variant="link" className="p-0 h-auto text-[10px] font-bold text-rose-600 uppercase tracking-widest hover:no-underline flex items-center gap-1">
            View Triage <ArrowRight className="w-3 h-3" />
          </Button>
        </div>
      )}

      {/* Security Bundles */}
      <div className="mt-2">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-foreground">Enhancements</h3>
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest cursor-pointer hover:text-primary transition-colors">View All</span>
        </div>

        <BundleCard 
          title="Deep Scan Bundle"
          description="Powered by neural sequence modeling for deeper payload analysis."
          price="49"
          icon={Sparkles}
          items={[
            { name: "CodeBERT Analysis", subtext: "Contextual inspection", image: null },
            { name: "Mutation Engine", subtext: "Dynamic payload generation", image: null }
          ]}
        />

        <BundleCard 
          title="Compliance Pack"
          description="Automated audit readiness for GDPR and PCI-DSS standards."
          price="129"
          icon={ShieldAlert}
          items={[
            { name: "GDPR Checker", subtext: "Privacy & Consent", image: null },
            { name: "Scan Scheduler", subtext: "Weekly compliance report", image: null }
          ]}
        />
      </div>

      {/* Floating help / promo */}
      <div className="mt-auto pt-6">
        <div className="bg-primary/5 rounded-2xl p-5 border border-primary/10">
          <h4 className="text-xs font-bold text-primary mb-2">Need a custom plan?</h4>
          <p className="text-[10px] text-muted-foreground leading-relaxed mb-4">
            Our security architects can design a tailormade infrastructure scan for your enterprise.
          </p>
          <Button className="w-full h-9 bg-primary text-white font-bold rounded-xl text-[10px] premium-shadow">
            Contact Security Ops
          </Button>
        </div>
      </div>
    </aside>
  );
}
