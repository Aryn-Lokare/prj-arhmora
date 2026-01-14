// frontend/components/auth/signup-form.jsx

"use client";

import { useState } from "react";
import Link from "next/link";
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

const signupSchema = z
    .object({
        firstName: z.string().min(2, "First name must be at least 2 characters"),
        lastName: z.string().min(2, "Last name must be at least 2 characters"),
        email: z.string().email("Please enter a valid email"),
        password: z
            .string()
            .min(8, "Password must be at least 8 characters")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/[a-z]/, "Password must contain at least one lowercase letter")
            .regex(/[0-9]/, "Password must contain at least one number"),
        confirmPassword: z.string(),
        acceptTerms: z.boolean().refine((val) => val === true, {
            message: "You must accept the terms and conditions",
        }),
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
        setValue,
        watch,
        formState: { errors },
    } = useForm({
        resolver: zodResolver(signupSchema),
        defaultValues: {
            firstName: "",
            lastName: "",
            email: "",
            password: "",
            confirmPassword: "",
            acceptTerms: false,
        },
    });

    const acceptTerms = watch("acceptTerms");

    const onSubmit = async (data) => {
        setIsLoading(true);
        setError("");

        try {
            const response = await registerUser(data);
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
        <div className="w-full max-w-[450px] flex flex-col items-center animate-in fade-in zoom-in duration-500">
            {/* Header Section */}
            <div className="text-center mb-5 w-full">
                <h1 className="text-[38px] font-bold text-[#0F172A] mb-1 tracking-tight leading-tight">Create Account</h1>
                <p className="text-[#64748B] text-base font-medium">Join us to start your secure journey</p>
            </div>

            {/* Google Login Section */}
            <div className="w-full mb-4">
                <GoogleLoginButton onError={(msg) => setError(msg)} />
            </div>

            {/* Divider */}
            <div className="w-full flex items-center gap-4 mb-4">
                <div className="flex-1 h-[1px] bg-[#E2E8F0]"></div>
                <span className="text-[#94A3B8] text-[11px] font-bold uppercase tracking-[0.05em] whitespace-nowrap">or Sign Up with Email</span>
                <div className="flex-1 h-[1px] bg-[#E2E8F0]"></div>
            </div>

            {/* Signup Form */}
            <form onSubmit={handleSubmit(onSubmit)} className="w-full space-y-3">
                {error && (
                    <div className="p-2.5 text-sm text-red-600 bg-red-50 border border-red-100 rounded-lg animate-in slide-in-from-top-2">
                        {error}
                    </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                        <Label htmlFor="firstName" className="text-sm font-bold text-[#1E293B]">First Name</Label>
                        <Input
                            id="firstName"
                            placeholder="John"
                            className="h-10 border-[#E2E8F0] rounded-lg focus-visible:ring-primary focus-visible:border-primary placeholder:text-[#94A3B8] transition-all"
                            {...register("firstName")}
                            disabled={isLoading}
                        />
                        {errors.firstName && (
                            <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.firstName.message}</p>
                        )}
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="lastName" className="text-sm font-bold text-[#1E293B]">Last Name</Label>
                        <Input
                            id="lastName"
                            placeholder="Doe"
                            className="h-10 border-[#E2E8F0] rounded-lg focus-visible:ring-primary focus-visible:border-primary placeholder:text-[#94A3B8] transition-all"
                            {...register("lastName")}
                            disabled={isLoading}
                        />
                        {errors.lastName && (
                            <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.lastName.message}</p>
                        )}
                    </div>
                </div>

                <div className="space-y-1.5">
                    <Label htmlFor="email" className="text-sm font-bold text-[#1E293B]">Email</Label>
                    <Input
                        id="email"
                        type="email"
                        placeholder="E.g. johndoe@email.com"
                        className="h-10 border-[#E2E8F0] rounded-lg focus-visible:ring-primary focus-visible:border-primary placeholder:text-[#94A3B8] transition-all"
                        {...register("email")}
                        disabled={isLoading}
                    />
                    {errors.email && (
                        <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.email.message}</p>
                    )}
                </div>

                <div className="space-y-1.5">
                    <Label htmlFor="password" className="text-sm font-bold text-[#1E293B]">Password</Label>
                    <div className="relative">
                        <Input
                            id="password"
                            type={showPassword ? "text" : "password"}
                            placeholder="Create a password"
                            className="h-10 border-[#E2E8F0] rounded-lg focus-visible:ring-primary focus-visible:border-primary placeholder:text-[#94A3B8] pr-10 transition-all"
                            {...register("password")}
                            disabled={isLoading}
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#64748B] transition-colors focus:outline-none"
                        >
                            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                    </div>
                    {errors.password && (
                        <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.password.message}</p>
                    )}
                </div>

                <div className="space-y-1.5">
                    <Label htmlFor="confirmPassword" className="text-sm font-bold text-[#1E293B]">Confirm Password</Label>
                    <div className="relative">
                        <Input
                            id="confirmPassword"
                            type={showConfirmPassword ? "text" : "password"}
                            placeholder="Confirm your password"
                            className="h-10 border-[#E2E8F0] rounded-lg focus-visible:ring-primary focus-visible:border-primary placeholder:text-[#94A3B8] pr-10 transition-all"
                            {...register("confirmPassword")}
                            disabled={isLoading}
                        />
                        <button
                            type="button"
                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#64748B] transition-colors focus:outline-none"
                        >
                            {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                    </div>
                    {errors.confirmPassword && (
                        <p className="text-[11px] text-red-500 font-medium px-1 mt-1">{errors.confirmPassword.message}</p>
                    )}
                </div>

                <div className="flex items-start space-x-3 py-0.5">
                    <Checkbox 
                        id="acceptTerms" 
                        checked={acceptTerms}
                        onCheckedChange={(checked) => setValue("acceptTerms", checked)}
                        disabled={isLoading}
                        className="mt-1 border-[#CBD5E1] rounded-md data-[state=checked]:bg-primary data-[state=checked]:border-primary transition-all" 
                    />
                    <div className="grid gap-1.5 leading-none">
                        <label
                            htmlFor="acceptTerms"
                            className="text-xs font-bold text-[#64748B] cursor-pointer select-none leading-normal"
                        >
                            I agree to the{" "}
                            <Link href="/terms" className="text-primary hover:underline">
                                Terms
                            </Link>{" "}
                            and{" "}
                            <Link href="/privacy" className="text-primary hover:underline">
                                Privacy Policy
                            </Link>
                        </label>
                        {errors.acceptTerms && (
                            <p className="text-[11px] text-red-500 font-medium mt-0.5">{errors.acceptTerms.message}</p>
                        )}
                    </div>
                </div>

                <Button 
                    type="submit" 
                    className="w-full h-11 bg-primary hover:bg-primary/90 text-white font-bold text-base rounded-lg border-none transition-all duration-200 shadow-sm active:scale-[0.98] mt-1"
                    disabled={isLoading}
                >
                    {isLoading ? "Creating account..." : "Create Account"}
                </Button>
            </form>

            {/* Footer */}
            <div className="mt-6 text-center">
                <p className="text-sm text-[#64748B] font-bold">
                    Already have an account?{" "}
                    <Link href="/login" className="text-primary font-bold hover:text-primary/80 transition-colors">
                        Log In
                    </Link>
                </p>
            </div>
        </div>
    );
}
