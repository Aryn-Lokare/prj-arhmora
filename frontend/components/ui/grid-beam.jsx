"use client";

import { motion } from "framer-motion";

export function GridBeam({ className }) {
  return (
    <div className={`absolute inset-0 overflow-hidden pointer-events-none ${className}`}>
      <svg className="w-full h-full opacity-[0.15]">
        <pattern
          id="grid-beam"
          width="64"
          height="64"
          patternUnits="userSpaceOnUse"
        >
          <path
            d="M 64 0 L 0 0 0 64"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
          />
        </pattern>
        <rect width="100%" height="100%" fill="url(#grid-beam)" />
      </svg>
      
      {/* Horizontal Beams */}
      {[...Array(5)].map((_, i) => (
        <motion.div
          key={`h-${i}`}
          className="absolute h-[1px] w-full bg-gradient-to-r from-transparent via-blue-500 to-transparent opacity-20"
          initial={{ top: `${20 * i + 10}%`, left: "-100%" }}
          animate={{ left: "100%" }}
          transition={{
            duration: 8 + i * 2,
            repeat: Infinity,
            ease: "linear",
            delay: i * 1.5,
          }}
        />
      ))}

      {/* Vertical Beams */}
      {[...Array(5)].map((_, i) => (
        <motion.div
          key={`v-${i}`}
          className="absolute w-[1px] h-full bg-gradient-to-b from-transparent via-blue-500 to-transparent opacity-20"
          initial={{ left: `${20 * i + 15}%`, top: "-100%" }}
          animate={{ top: "100%" }}
          transition={{
            duration: 10 + i * 2,
            repeat: Infinity,
            ease: "linear",
            delay: i * 2,
          }}
        />
      ))}
    </div>
  );
}
