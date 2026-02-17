// frontend/app/layout.js

import React from "react";
import { Inter, Source_Sans_3 } from "next/font/google";
import { AuthProvider } from "@/components/providers/auth-provider";
import { GoogleProvider } from "@/components/providers/google-provider";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const sourceSans3 = Source_Sans_3({
  subsets: ["latin"],
  variable: "--font-source-sans",
});

export const metadata = {
  title: "Arhmora",
  description: "Next.js with Django Authentication",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body
        className={`${inter.variable} ${sourceSans3.variable} font-sans`}
      >
        <GoogleProvider>
          <AuthProvider>
            {children}
          </AuthProvider>
        </GoogleProvider>
      </body>
    </html>
  );
}
