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
import { Checkbox } from "@/components/ui/checkbox";
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
        <div className="w-full max-w-[400px] flex flex-col items-center animate-in fade-in zoom-in duration-500">
            {/* Header Section */}
            <div className="text-center mb-8 w-full flex flex-col items-center">
                <div className="mb-4">
                    <Image src="/logo.png" alt="Arhmora" width={48} height={48} className="w-12 h-12 object-contain" />
                </div>
                <h1 className="text-[48px] font-bold text-[#0F172A] mb-2 tracking-tight leading-tight font-heading">Login</h1>
                <p className="text-[#64748B] text-base font-medium">Hi, Welcome back</p>
            </div>

            {/* Google Login Section */}
            <div className="w-full mb-6">
                <GoogleLoginButton onError={(msg) => setError(msg)} />
            </div>

            {/* Divider */}
            <div className="w-full flex items-center gap-4 mb-6">
                <div className="flex-1 h-[1px] bg-[#E2E8F0]"></div>
                <span className="text-[#64748B] text-xs font-semibold uppercase tracking-wide whitespace-nowrap">or Login with Email</span>
                <div className="flex-1 h-[1px] bg-[#E2E8F0]"></div>
            </div>

            {/* Login Form */}
            <form onSubmit={handleSubmit(onSubmit)} className="w-full space-y-4">
                {/* Error Alert */}
                {error && (
                    <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-100 rounded-xl animate-in slide-in-from-top-2">
                        {error}
                    </div>
                )}

                {/* Email Field */}
                <div className="space-y-2">
                    <Label htmlFor="email" className="text-sm font-bold text-[#0F172A]">Email</Label>
                    <Input
                        id="email"
                        type="email"
                        placeholder="E.g. johndoe@email.com"
                        className="h-11 border-[#E2E8F0] rounded-xl focus-visible:ring-[#2D5BFF] focus-visible:border-[#2D5BFF] placeholder:text-[#64748B] transition-all duration-200"
                        {...register("email")}
                        disabled={isLoading}
                    />
                    {errors.email && (
                        <p className="text-xs text-red-500 font-medium px-1">{errors.email.message}</p>
                    )}
                </div>

                {/* Password Field */}
                <div className="space-y-2">
                    <Label htmlFor="password" className="text-sm font-bold text-[#0F172A]">Password</Label>
                    <div className="relative">
                        <Input
                            id="password"
                            type={showPassword ? "text" : "password"}
                            placeholder="Enter your password"
                            className="h-11 border-[#E2E8F0] rounded-xl focus-visible:ring-[#2D5BFF] focus-visible:border-[#2D5BFF] placeholder:text-[#64748B] pr-10 transition-all duration-200"
                            {...register("password")}
                            disabled={isLoading}
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-[#64748B] hover:text-[#334155] transition-colors duration-200 focus:outline-none"
                        >
                            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                    </div>
                    {errors.password && (
                        <p className="text-xs text-red-500 font-medium px-1">{errors.password.message}</p>
                    )}
                </div>

                {/* Remember Me & Forgot Password */}
                <div className="flex items-center justify-between py-1">
                    <div className="flex items-center space-x-2">
                        <Checkbox id="remember" className="border-[#E2E8F0] rounded data-[state=checked]:bg-[#2D5BFF] data-[state=checked]:border-[#2D5BFF] transition-all duration-200" />
                        <label
                            htmlFor="remember"
                            className="text-sm font-semibold text-[#64748B] cursor-pointer select-none"
                        >
                            Remember Me
                        </label>
                    </div>
                    <Link
                        href="/forgot-password"
                        className="text-sm font-semibold text-[#2D5BFF] hover:text-[#1D4ED8] transition-colors duration-200"
                    >
                        Forgot Password?
                    </Link>
                </div>

                {/* Submit Button */}
                <Button 
                    type="submit" 
                    className="w-full h-11 bg-[#2D5BFF] hover:bg-[#1D4ED8] text-white font-bold text-base rounded-xl border-none transition-all duration-200 shadow-sm active:scale-[0.98]"
                    disabled={isLoading}
                >
                    {isLoading ? "Logging in..." : "Login"}
                </Button>
            </form>

            {/* Footer */}
            <div className="mt-6 text-center">
                <p className="text-sm text-[#64748B] font-semibold">
                    Not registered yet?{" "}
                    <Link href="/signup" className="text-[#2D5BFF] font-bold hover:text-[#1D4ED8] transition-colors duration-200">
                        Create an account
                    </Link>
                </p>
            </div>
        </div>
    );
}
