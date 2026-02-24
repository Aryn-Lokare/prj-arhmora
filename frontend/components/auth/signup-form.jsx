// frontend/components/auth/signup-form.jsx

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

const signupSchema = z
    .object({
        name: z.string().min(2, "Full name must be at least 2 characters"),
        email: z.string().email("Please enter a valid email"),
        password: z
            .string()
            .min(8, "Password must be at least 8 characters")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/[a-z]/, "Password must contain at least one lowercase letter")
            .regex(/[0-9]/, "Password must contain at least one number"),
        confirmPassword: z.string().min(1, "Please confirm your password"),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: "Passwords don't match",
        path: ["confirmPassword"],
    });

export function SignupForm() {
    const { register: registerUser } = useAuth();
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm({
        resolver: zodResolver(signupSchema),
        defaultValues: {
            name: "",
            email: "",
            password: "",
            confirmPassword: "",
        },
    });

    const onSubmit = async (data) => {
        setIsLoading(true);
        setError("");

        // Split name for compatibility with existing registerUser which might expect firstName/lastName
        const nameParts = data.name.trim().split(" ");
        const registrationData = {
            ...data,
            firstName: nameParts[0],
            lastName: nameParts.slice(1).join(" ") || ".",
        };

        try {
            const response = await registerUser(registrationData);
            if (!response.success) {
                setError(response.message || "Registration failed");
            }
        } catch (err) {
            const errorMessage =
                err.response?.data?.message ||
                Object.values(err.response?.data || {}).flat().join(", ") ||
                "An error occurred";
            setError(errorMessage);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="w-full max-w-[440px] flex flex-col items-center animate-in fade-in zoom-in duration-500">
            {/* Form Card */}
            <div className="w-full bg-white dark:bg-[#131415] rounded-3xl p-10 card-shadow border border-[#e2e8f0] dark:border-[#2a2b2c] transition-colors duration-300">
                <div className="text-center mb-8">
                    <h1 className="text-[30px] font-bold text-[#131415] dark:text-white mb-2 font-heading tracking-tight leading-none">Create Account</h1>
                    <p className="text-[#767a8c] dark:text-[#94a3b8] text-sm font-medium">Start your secure journey with Arhmora</p>
                </div>

                {/* Signup Form */}
                <form onSubmit={handleSubmit(onSubmit)} className="w-full space-y-5">
                    {error && (
                        <div className="p-3 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/20 rounded-xl animate-in slide-in-from-top-2">
                            {error}
                        </div>
                    )}

                    {/* Name Field */}
                    <div className="space-y-1.5">
                        <Label htmlFor="name" className="text-[12px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Full Name</Label>
                        <Input
                            id="name"
                            placeholder="John Doe"
                            className="h-11 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all"
                            {...register("name")}
                            disabled={isLoading}
                        />
                        {errors.name && (
                            <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.name.message}</p>
                        )}
                    </div>

                    {/* Email Field */}
                    <div className="space-y-1.5">
                        <Label htmlFor="email" className="text-[12px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Email Address</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="johndoe@email.com"
                            className="h-11 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] transition-all"
                            {...register("email")}
                            disabled={isLoading}
                        />
                        {errors.email && (
                            <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.email.message}</p>
                        )}
                    </div>

                    {/* Password Fields Row */}
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                            <Label htmlFor="password" className="text-[12px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Password</Label>
                            <div className="relative">
                                <Input
                                    id="password"
                                    type={showPassword ? "text" : "password"}
                                    placeholder="••••••••"
                                    className="h-11 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] pr-10 transition-all font-mono"
                                    {...register("password")}
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#94a3b8] dark:text-[#64748b] hover:text-[#4b5666] dark:hover:text-white focus:outline-none"
                                >
                                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                                </button>
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <Label htmlFor="confirmPassword" className="text-[12px] font-bold text-[#131415] dark:text-white uppercase tracking-wider opacity-70">Confirm</Label>
                            <div className="relative">
                                <Input
                                    id="confirmPassword"
                                    type={showConfirmPassword ? "text" : "password"}
                                    placeholder="••••••••"
                                    className="h-11 border-[#eaecf0] dark:border-[#2a2b2c] bg-[#f9fafb] dark:bg-[#1a1b1c] dark:text-white rounded-xl focus-visible:ring-[#1153ed] focus-visible:border-[#1153ed] placeholder:text-[#94a3b8] pr-10 transition-all font-mono"
                                    {...register("confirmPassword")}
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#94a3b8] dark:text-[#64748b] hover:text-[#4b5666] dark:hover:text-white focus:outline-none"
                                >
                                    {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    {/* Compact error reporting for password matches */}
                    {(errors.password || errors.confirmPassword) && (
                        <p className="text-[11px] text-red-500 font-medium px-1">
                            {errors.password?.message || errors.confirmPassword?.message}
                        </p>
                    )}

                    <div className="pt-2 flex flex-col gap-3">
                        <Button 
                            type="submit" 
                            className="w-full h-11 bg-[#1153ed] dark:bg-blue-600 hover:bg-[#03569d] dark:hover:bg-blue-500 text-white font-bold text-base rounded-xl border-none transition-all duration-300 shadow-md active:scale-[0.98]"
                            disabled={isLoading}
                        >
                            {isLoading ? "creating account..." : "Create Account"}
                        </Button>

                        <div className="w-full flex items-center gap-3 my-2">
                            <div className="flex-1 h-[1px] bg-[#f2f4f7] dark:bg-[#2a2b2c]"></div>
                            <span className="text-[#94a3b8] dark:text-[#64748b] text-[10px] font-bold uppercase tracking-widest leading-none bg-white dark:bg-[#131415] px-2 transition-colors">or</span>
                            <div className="flex-1 h-[1px] bg-[#f2f4f7] dark:bg-[#2a2b2c]"></div>
                        </div>

                        <GoogleLoginButton onError={(msg) => setError(msg)} />
                    </div>
                </form>

                {/* Footer */}
                <div className="mt-8 pt-6 border-t border-[#f2f4f7] dark:border-[#2a2b2c] text-center">
                    <p className="text-sm text-[#767a8c] dark:text-[#94a3b8] font-bold">
                        Already joined?{" "}
                        <Link href="/login" className="text-[#1153ed] dark:text-blue-400 font-bold hover:text-[#03569d] dark:hover:text-blue-300 transition-colors ml-1">
                            Log In
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    );
}
