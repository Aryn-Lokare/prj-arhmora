"use client";

import React from "react";
import { cn } from "@/lib/utils";

/**
 * A lightweight Markdown-lite renderer for security findings.
 * Handles bold, inline code, code blocks, and lists.
 */
export function Markdown({ content, className }) {
  if (!content) return null;

  // 1. Process Code Blocks (```)
  const processCodeBlocks = (text) => {
    const parts = text.split(/```(\w*)\n?([\s\S]*?)```/g);
    const result = [];

    for (let i = 0; i < parts.length; i++) {
      if (i % 3 === 0) {
        // Regular text
        if (parts[i]) result.push({ type: "text", content: parts[i] });
      } else if (i % 3 === 1) {
        // Language (ignored for now, but captured)
      } else {
        // Code content
        result.push({ type: "code-block", content: parts[i], lang: parts[i-1] });
      }
    }
    return result;
  };

  // 2. Process Lines (Lists, Bold, Inline Code)
  const renderTextSegment = (text) => {
    // Handle Bold (**text**)
    let processed = text;
    
    // Split by bold patterns
    const boldParts = processed.split(/(\*\*.*?\*\*)/g);
    return boldParts.map((part, i) => {
      if (part.startsWith("**") && part.endsWith("**")) {
        return <strong key={i} className="font-black text-[#131415]">{part.slice(2, -2)}</strong>;
      }
      
      // Handle Inline Code (`code`)
      const codeParts = part.split(/(`.*?`)/g);
      return codeParts.map((cPart, j) => {
        if (cPart.startsWith("`") && cPart.endsWith("`")) {
          return (
            <code key={`${i}-${j}`} className="bg-slate-100 text-[#1153ed] px-1.5 py-0.5 rounded-md font-mono text-[0.9em]">
              {cPart.slice(1, -1)}
            </code>
          );
        }
        return cPart;
      });
    });
  };

  const segments = processCodeBlocks(content);

  return (
    <div className={cn("flex flex-col gap-4 text-[#334155] leading-relaxed", className)}>
      {segments.map((segment, idx) => {
        if (segment.type === "code-block") {
          return (
            <div key={idx} className="my-2 group relative">
              <div className="absolute top-0 right-4 -translate-y-1/2 bg-[#1153ed] text-white text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-opacity">
                {segment.lang || "code"}
              </div>
              <pre className="bg-[#0f172a] text-[#e2e8f0] p-4 rounded-xl font-mono text-[13px] overflow-x-auto shadow-inner border border-slate-800">
                <code>{segment.content.trim()}</code>
              </pre>
            </div>
          );
        }

        // Process lines in text segment
        const lines = segment.content.split("\n");
        return (
          <div key={idx} className="flex flex-col gap-2">
            {lines.map((line, lIdx) => {
              const trimmedLine = line.trim();
              if (!trimmedLine) return <div key={lIdx} className="h-2" />;

              // Bullet List
              if (trimmedLine.startsWith("* ") || trimmedLine.startsWith("- ")) {
                return (
                  <div key={lIdx} className="flex gap-3 pl-2">
                    <span className="text-[#1153ed] font-black mt-1.5 shrink-0 w-1.5 h-1.5 rounded-full bg-[#1153ed]" />
                    <span className="flex-1">{renderTextSegment(trimmedLine.slice(2))}</span>
                  </div>
                );
              }

              // Numbered List (Simple regex for 1., 2.)
              if (/^\d+\.\s/.test(trimmedLine)) {
                const numMatch = trimmedLine.match(/^(\d+\.)\s(.*)/);
                return (
                  <div key={lIdx} className="flex gap-3 pl-2">
                    <span className="text-[#1153ed] font-bold shrink-0 min-w-[20px]">{numMatch[1]}</span>
                    <span className="flex-1">{renderTextSegment(numMatch[2])}</span>
                  </div>
                );
              }

              return <p key={lIdx}>{renderTextSegment(line)}</p>;
            })}
          </div>
        );
      })}
    </div>
  );
}
