// frontend/app/(auth)/reset-password/page.jsx

"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { authService } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const schema = z
  .object({
    password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
      .regex(/[a-z]/, "Password must contain at least one lowercase letter")
      .regex(/[0-9]/, "Password must contain at least one number"),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });

// Inner component that uses useSearchParams — must be wrapped in Suspense
function ResetPasswordContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get("token");

  const [status, setStatus] = useState("validating"); // validating, valid, invalid, success
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [userEmail, setUserEmail] = useState("");

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(schema),
  });

  // Validate token on page load
  useEffect(() => {
    if (!token) {
      setStatus("invalid");
      setError("No reset token provided.");
      return;
    }

    const validateToken = async () => {
      try {
        const response = await authService.validateResetToken(token);
        if (response.success) {
          setStatus("valid");
          setUserEmail(response.data.email);
        } else {
          setStatus("invalid");
          setError(response.message);
        }
      } catch (err) {
        setStatus("invalid");
        setError(
          err.response?.data?.message || "Invalid or expired reset link.",
        );
      }
    };

    validateToken();
  }, [token]);

  const onSubmit = async (data) => {
    setIsLoading(true);
    setError("");

    try {
      const response = await authService.resetPassword(
        token,
        data.password,
        data.confirmPassword,
      );

      if (response.success) {
        setStatus("success");
      } else {
        setError(response.message);
      }
    } catch (err) {
      setError(err.response?.data?.message || "Failed to reset password");
    } finally {
      setIsLoading(false);
    }
  };

  // Loading state
  if (status === "validating") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#f2f4f7] dark:bg-[#0a0a0b] p-4 transition-colors duration-300">
        <Card className="w-full max-w-md bg-white dark:bg-[#131415] border-[#e2e8f0] dark:border-[#2a2b2c] rounded-[32px] p-10 soft-shadow">
          <CardHeader>
            <div className="flex justify-center mb-6">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#1153ed] dark:border-blue-400"></div>
            </div>
            <CardTitle className="text-xl font-bold text-center text-[#131415] dark:text-white">
              Validating reset link...
            </CardTitle>
          </CardHeader>
        </Card>
      </div>
    );
  }

  // Invalid token
  if (status === "invalid") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#f2f4f7] dark:bg-[#0a0a0b] p-4 transition-colors duration-300">
        <Card className="w-full max-w-md bg-white dark:bg-[#131415] border-[#e2e8f0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden soft-shadow">
          <CardHeader className="pt-10">
            <div className="flex justify-center mb-6">
              <div className="h-16 w-16 rounded-3xl bg-red-50 dark:bg-red-900/10 flex items-center justify-center border border-red-100 dark:border-red-900/20">
                <svg
                  className="h-8 w-8 text-red-600 dark:text-red-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </div>
            </div>
            <CardTitle className="text-2xl font-bold text-center text-red-600 dark:text-red-400">
              Invalid Reset Link
            </CardTitle>
            <CardDescription className="text-center text-[#767a8c] dark:text-[#94a3b8] font-medium mt-2">{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-sm text-[#767a8c] dark:text-[#94a3b8] text-center font-medium">
                This reset link may have expired or already been used.
              </p>
              <Button
                className="w-full h-12 bg-[#1153ed] dark:bg-blue-600 hover:bg-[#03569d] dark:hover:bg-blue-500 text-white font-bold rounded-xl border-none transition-all duration-300 shadow-md active:scale-[0.98]"
                onClick={() => router.push("/forgot-password")}
              >
                Request New Reset Link
              </Button>
            </div>
          </CardContent>
          <CardFooter className="flex justify-center pb-10">
            <Link
              href="/login"
              className="text-sm font-bold text-[#1153ed] dark:text-blue-400 hover:text-[#03569d] dark:hover:text-blue-300 transition-colors"
            >
              Back to Login
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  // Success state
  if (status === "success") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#f2f4f7] dark:bg-[#0a0a0b] p-4 transition-colors duration-300">
        <Card className="w-full max-w-md bg-white dark:bg-[#131415] border-[#e2e8f0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden soft-shadow">
          <CardHeader className="pt-10">
            <div className="flex justify-center mb-6">
              <div className="h-16 w-16 rounded-3xl bg-green-50 dark:bg-green-900/10 flex items-center justify-center border border-green-100 dark:border-green-900/20">
                <svg
                  className="h-8 w-8 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
            </div>
            <CardTitle className="text-2xl font-bold text-center text-green-600 dark:text-green-400">
              Reset Successful!
            </CardTitle>
            <CardDescription className="text-center text-[#767a8c] dark:text-[#94a3b8] font-medium mt-2">
              Your password has been changed successfully.
            </CardDescription>
          </CardHeader>
          <CardContent className="pb-10">
            <Button className="w-full h-12 bg-[#1153ed] dark:bg-blue-600 hover:bg-[#03569d] dark:hover:bg-blue-500 text-white font-bold rounded-xl border-none transition-all duration-300 shadow-md active:scale-[0.98]" onClick={() => router.push("/login")}>
              Continue to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Password reset form
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#f2f4f7] dark:bg-[#0a0a0b] p-4 transition-colors duration-300">
      <Card className="w-full max-w-md bg-white dark:bg-[#131415] border-[#e2e8f0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden soft-shadow">
        <CardHeader className="pt-10">
          <div className="flex justify-center mb-6">
            <div className="h-16 w-16 rounded-3xl bg-[#f2f4f7] dark:bg-[#1e293b] flex items-center justify-center border border-[#eaecf0] dark:border-[#2a2b2c]">
              <svg
                className="h-8 w-8 text-[#767a8c] dark:text-[#94a3b8]"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                />
              </svg>
            </div>
          </div>
          <CardTitle className="text-2xl font-bold text-center text-[#131415] dark:text-white">
            Reset password
          </CardTitle>
          <CardDescription className="text-center text-[#767a8c] dark:text-[#94a3b8] font-medium mt-2">
            Enter a new password for <strong className="text-[#131415] dark:text-white">{userEmail}</strong>
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            {error && (
              <div className="p-3 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/20 rounded-xl">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="password" className="text-[13px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">New Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                className="h-12 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all"
                {...register("password")}
                disabled={isLoading}
              />
              {errors.password && (
                <p className="text-xs text-red-500 font-medium px-1">
                  {errors.password.message}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-[13px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Confirm New Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="••••••••"
                className="h-12 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all"
                {...register("confirmPassword")}
                disabled={isLoading}
              />
              {errors.confirmPassword && (
                <p className="text-xs text-red-500 font-medium px-1">
                  {errors.confirmPassword.message}
                </p>
              )}
            </div>

            {/* Password requirements */}
            <div className="bg-[#f2f4f7] dark:bg-[#1a1b1c] rounded-xl p-5 border border-[#eaecf0] dark:border-[#2a2b2c]">
              <p className="text-xs font-bold text-[#131415] dark:text-white uppercase tracking-widest mb-3 opacity-70">
                Requirements:
              </p>
              <ul className="text-[11px] text-[#767a8c] dark:text-[#94a3b8] space-y-2 font-bold">
                <li className="flex items-center gap-2">
                  <div className="w-1 h-1 rounded-full bg-[#1153ed] dark:bg-blue-400"></div> 8+ characters
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1 h-1 rounded-full bg-[#1153ed] dark:bg-blue-400"></div> One uppercase letter
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1 h-1 rounded-full bg-[#1153ed] dark:bg-blue-400"></div> One lowercase letter
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1 h-1 rounded-full bg-[#1153ed] dark:bg-blue-400"></div> One number
                </li>
              </ul>
            </div>

            <Button 
                type="submit" 
                className="w-full h-12 bg-[#1153ed] dark:bg-blue-600 hover:bg-[#03569d] dark:hover:bg-blue-500 text-white font-bold text-base rounded-xl border-none transition-all duration-300 shadow-md active:scale-[0.98]" 
                disabled={isLoading}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                  Resetting...
                </span>
              ) : (
                "Reset Password"
              )}
            </Button>
          </form>
        </CardContent>

        <CardFooter className="flex justify-center pb-10">
          <Link href="/login" className="text-sm font-bold text-[#1153ed] dark:text-blue-400 hover:text-[#03569d] dark:hover:text-blue-300 transition-colors">
            Back to Login
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}

// Fallback shown while loading — keeps the same "validating" card style
function ResetPasswordFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex justify-center mb-4">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          </div>
          <CardTitle className="text-xl text-center">Loading...</CardTitle>
        </CardHeader>
      </Card>
    </div>
  );
}

// Default export wraps inner component in Suspense to satisfy Next.js App Router requirement
export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<ResetPasswordFallback />}>
      <ResetPasswordContent />
    </Suspense>
  );
}
