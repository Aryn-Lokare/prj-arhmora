// frontend/app/layout.js

import React from "react";
import { Inter } from "next/font/google";
import { AuthProvider } from "@/components/providers/auth-provider";
import { GoogleProvider } from "@/components/providers/google-provider";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata = {
  title: "My App",
  description: "Next.js with Django Authentication",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <GoogleProvider>
          <AuthProvider>
            {children}
          </AuthProvider>
        </GoogleProvider>
      </body>
    </html>
  );
}
