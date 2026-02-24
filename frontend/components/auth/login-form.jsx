// frontend/components/auth/login-form.jsx

"use client";

import { useState } from "react";
import Link from "next/link";
import Image from "next/image";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";

import { useAuth } from "@/components/providers/auth-provider";
import { GoogleLoginButton } from "@/components/auth/google-login-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, EyeOff } from "lucide-react";

const loginSchema = z.object({
    email: z.string().email("Please enter a valid email"),
    password: z.string().min(1, "Password is required"),
});

export function LoginForm() {
    const { login } = useAuth();
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm({
        resolver: zodResolver(loginSchema),
        defaultValues: {
            email: "",
            password: "",
        },
    });

    const onSubmit = async (data) => {
        setIsLoading(true);
        setError("");

        try {
            const response = await login(data.email, data.password);
            if (!response.success) {
                setError(response.message || "Login failed");
            }
        } catch (err) {
            setError(err.response?.data?.message || "An error occurred");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="w-full max-w-[420px] flex flex-col items-center animate-in fade-in zoom-in duration-500">
            {/* Form Card */}
            <div className="w-full bg-white dark:bg-[#131415] rounded-3xl p-10 card-shadow border border-[#e2e8f0] dark:border-[#2a2b2c] transition-colors duration-300">
                <div className="text-center mb-10">
                    <h1 className="text-[32px] font-bold text-[#131415] dark:text-white mb-2 font-heading tracking-tight leading-none">Log in</h1>
                    <p className="text-[#767a8c] dark:text-[#94a3b8] text-sm font-medium">Safe in, Secure out. Arhmora</p>
                </div>

                {/* Login Form */}
                <form onSubmit={handleSubmit(onSubmit)} className="w-full space-y-6">
                    {/* Error Alert */}
                    {error && (
                        <div className="p-3 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/20 rounded-xl animate-in slide-in-from-top-2">
                            {error}
                        </div>
                    )}

                    {/* Email Field */}
                    <div className="space-y-2">
                        <Label htmlFor="email" className="text-[13px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Email Address</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="johndoe@email.com"
                            className="h-12 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all duration-200"
                            {...register("email")}
                            disabled={isLoading}
                        />
                        {errors.email && (
                            <p className="text-xs text-red-500 font-medium px-1">{errors.email.message}</p>
                        )}
                    </div>

                    {/* Password Field */}
                    <div className="space-y-2">
                        <div className="flex items-center justify-between px-1">
                            <Label htmlFor="password" className="text-[13px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Password</Label>
                            <Link
                                href="/forgot-password"
                                className="text-[13px] font-bold text-[#1153ed] dark:text-blue-400 hover:text-[#03569d] dark:hover:text-blue-300 transition-colors duration-200"
                            >
                                Forgot?
                            </Link>
                        </div>
                        <div className="relative">
                            <Input
                                id="password"
                                type={showPassword ? "text" : "password"}
                                placeholder="••••••••"
                                className="h-12 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] pr-12 transition-all duration-200"
                                {...register("password")}
                                disabled={isLoading}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-4 top-1/2 -translate-y-1/2 text-[#94a3b8] dark:text-[#64748b] hover:text-[#4b5666] dark:hover:text-white transition-colors duration-200 focus:outline-none"
                            >
                                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                            </button>
                        </div>
                        {errors.password && (
                            <p className="text-xs text-red-500 font-medium px-1">{errors.password.message}</p>
                        )}
                    </div>

                    {/* Submit Button */}
                    <div className="space-y-4">
                        <Button 
                            type="submit" 
                            className="w-full h-12 bg-[#1153ed] dark:bg-blue-600 hover:bg-[#03569d] dark:hover:bg-blue-500 text-white font-bold text-base rounded-xl border-none transition-all duration-300 shadow-md active:scale-[0.98]"
                            disabled={isLoading}
                        >
                            {isLoading ? "Authenticating..." : "Login"}
                        </Button>

                        <div className="relative flex items-center justify-center py-2">
                            <div className="absolute inset-0 flex items-center">
                                <span className="w-full border-t border-[#f2f4f7] dark:border-[#2a2b2c]" />
                            </div>
                            <span className="relative bg-white dark:bg-[#131415] px-4 text-[11px] font-bold text-[#b4b7c1] dark:text-[#64748b] uppercase tracking-widest transition-colors">
                                Or continue with
                            </span>
                        </div>

                        <GoogleLoginButton 
                            onError={setError} 
                            onSuccess={() => {}} // Redirection handled inside the component
                        />
                    </div>
                </form>

                {/* Footer Section in Card */}
                <div className="mt-8 pt-8 border-t border-[#f2f4f7] dark:border-[#2a2b2c] text-center">
                    <p className="text-sm text-[#767a8c] dark:text-[#94a3b8] font-semibold">
                        Don't have an account?{" "}
                        <Link href="/signup" className="text-[#1153ed] dark:text-blue-400 font-bold hover:text-[#03569d] transition-colors duration-200 ml-1">
                            Create account
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    );
}
