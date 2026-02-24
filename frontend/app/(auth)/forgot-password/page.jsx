// frontend/app/(auth)/forgot-password/page.jsx

"use client";

import { useState } from "react";
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

const schema = z.object({
    email: z.string().email("Please enter a valid email address"),
});

export default function ForgotPasswordPage() {
    const [isLoading, setIsLoading] = useState(false);
    const [isSuccess, setIsSuccess] = useState(false);
    const [error, setError] = useState("");

    const {
        register,
        handleSubmit,
        formState: { errors },
        getValues,
    } = useForm({
        resolver: zodResolver(schema),
    });

    const onSubmit = async (data) => {
        setIsLoading(true);
        setError("");

        try {
            const response = await authService.forgotPassword(data.email);
            if (response.success) {
                setIsSuccess(true);
            } else {
                setError(response.message);
            }
        } catch (err) {
            setError(err.response?.data?.message || "Failed to send reset email");
        } finally {
            setIsLoading(false);
        }
    };

    if (isSuccess) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-[#f2f4f7] dark:bg-[#0a0a0b] p-4 transition-colors duration-300">
                <Card className="w-full max-w-md bg-white dark:bg-[#131415] border-[#e2e8f0] dark:border-[#2a2b2c] rounded-[32px] overflow-hidden soft-shadow">
                    <CardHeader className="pt-10">
                        <div className="flex justify-center mb-6">
                            <div className="h-16 w-16 rounded-3xl bg-blue-50 dark:bg-blue-900/10 flex items-center justify-center border border-blue-100 dark:border-blue-900/20">
                                <svg
                                    className="h-8 w-8 text-[#1153ed] dark:text-blue-400"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth={2}
                                        d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                                    />
                                </svg>
                            </div>
                        </div>
                        <CardTitle className="text-2xl font-bold text-center text-[#131415] dark:text-white">Check your email</CardTitle>
                        <CardDescription className="text-center text-[#767a8c] dark:text-[#94a3b8] font-medium mt-2">
                            We&apos;ve sent a password reset link to <strong className="text-[#131415] dark:text-white">{getValues("email")}</strong>
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                            <p className="text-sm text-[#767a8c] dark:text-[#94a3b8] text-center font-medium">
                                Click the link in the email to reset your password. The link will expire in 1 hour.
                            </p>

                            <div className="bg-[#fefce8] dark:bg-yellow-900/10 border border-[#fef08a] dark:border-yellow-900/20 rounded-xl p-4">
                                <p className="text-xs text-[#854d0e] dark:text-yellow-500 font-medium">
                                    <strong className="font-bold">Didn&apos;t receive the email?</strong>
                                    <br />
                                    Check your spam folder or{" "}
                                    <button
                                        onClick={() => setIsSuccess(false)}
                                        className="text-[#1153ed] dark:text-blue-400 font-bold hover:underline"
                                    >
                                        try again
                                    </button>
                                </p>
                            </div>
                        </div>
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
                    <CardTitle className="text-2xl font-bold text-center text-[#131415] dark:text-white">Forgot password?</CardTitle>
                    <CardDescription className="text-center text-[#767a8c] dark:text-[#94a3b8] font-medium mt-2">
                        No worries! Enter your email and we&apos;ll send you a reset link.
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
                            <Label htmlFor="email" className="text-[13px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Email Address</Label>
                            <Input
                                id="email"
                                type="email"
                                placeholder="john@example.com"
                                className="h-12 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all"
                                {...register("email")}
                                disabled={isLoading}
                            />
                            {errors.email && (
                                <p className="text-xs text-red-500 font-medium px-1">{errors.email.message}</p>
                            )}
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
                                    Sending...
                                </span>
                            ) : (
                                "Send Reset Link"
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
