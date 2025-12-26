// frontend/app/layout.js

import React from "react";
import { Inter } from "next/font/google";
import { AuthProvider } from "@/components/providers/auth-provider";
import { GoogleProvider } from "@/components/providers/google-provider";
import { Header } from "@/components/layout/header";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata = {
  title: "Arhmora",
  description: "Next.js with Django Authentication",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <GoogleProvider>
          <AuthProvider>
            <Header />
            <main className="pt-16">
              {children}
            </main>
          </AuthProvider>
        </GoogleProvider>
      </body>
    </html>
  );
}
