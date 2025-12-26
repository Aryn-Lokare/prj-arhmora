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
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

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

    const handleGoogleError = (message) => {
        setError(message);
    };

    return (
        <Card className="w-full max-w-md tech-card border-t-4 border-t-primary">
            <CardHeader className="space-y-1">
                <div className="flex justify-center mb-4">
                    <div className="px-3 py-1 bg-primary/10 border border-primary/20 rounded-sm">
                        <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-primary font-bold">New Account</span>
                    </div>
                </div>
                <CardTitle className="text-2xl font-bold text-center tracking-tight">
                    Create Account
                </CardTitle>
                <CardDescription className="text-center font-mono text-[11px] uppercase tracking-wider">
                    Sign up to start using our platform
                </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
                {/* Error Alert */}
                {error && (
                    <div className="p-3 text-[12px] font-mono text-red-600 bg-red-50 border border-red-200 rounded-sm">
                        <span className="font-bold mr-2">[ERROR]</span>{error}
                    </div>
                )}

                {/* Google Login Button */}
                <div className="rounded-sm overflow-hidden">
                    <GoogleLoginButton onError={handleGoogleError} />
                </div>

                {/* Divider */}
                <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                        <div className="w-full border-t border-border/60"></div>
                    </div>
                    <div className="relative flex justify-center text-[10px] font-mono uppercase tracking-widest">
                        <span className="px-2 bg-background text-muted-foreground">Standard Sign Up</span>
                    </div>
                </div>

                {/* Signup Form */}
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                    {/* Name Fields */}
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                            <Label htmlFor="firstName" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">First Name</Label>
                            <Input
                                id="firstName"
                                placeholder="John"
                                className="rounded-sm border-border/60 focus:ring-1 font-mono text-sm placeholder:opacity-30"
                                {...register("firstName")}
                                disabled={isLoading}
                            />
                            {errors.firstName && (
                                <p className="text-[10px] font-mono text-red-500 uppercase">{errors.firstName.message}</p>
                            )}
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="lastName" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Last Name</Label>
                            <Input
                                id="lastName"
                                placeholder="Doe"
                                className="rounded-sm border-border/60 focus:ring-1 font-mono text-sm placeholder:opacity-30"
                                {...register("lastName")}
                                disabled={isLoading}
                            />
                            {errors.lastName && (
                                <p className="text-[10px] font-mono text-red-500 uppercase">{errors.lastName.message}</p>
                            )}
                        </div>
                    </div>

                    {/* Email */}
                    <div className="space-y-1.5">
                        <Label htmlFor="email" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Email Address</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="user@example.com"
                            className="rounded-sm border-border/60 focus:ring-1 font-mono text-sm placeholder:opacity-30"
                            {...register("email")}
                            disabled={isLoading}
                        />
                        {errors.email && (
                            <p className="text-[10px] font-mono text-red-500 uppercase">{errors.email.message}</p>
                        )}
                    </div>

                    {/* Password */}
                    <div className="space-y-1.5">
                        <Label htmlFor="password" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Password</Label>
                        <Input
                            id="password"
                            type="password"
                            placeholder="••••••••"
                            className="rounded-sm border-border/60 focus:ring-1 font-mono text-sm"
                            {...register("password")}
                            disabled={isLoading}
                        />
                        {errors.password && (
                            <p className="text-[10px] font-mono text-red-500 uppercase">{errors.password.message}</p>
                        )}
                    </div>

                    {/* Confirm Password */}
                    <div className="space-y-1.5">
                        <Label htmlFor="confirmPassword" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Confirm Password</Label>
                        <Input
                            id="confirmPassword"
                            type="password"
                            placeholder="••••••••"
                            className="rounded-sm border-border/60 focus:ring-1 font-mono text-sm"
                            {...register("confirmPassword")}
                            disabled={isLoading}
                        />
                        {errors.confirmPassword && (
                            <p className="text-[10px] font-mono text-red-500 uppercase">{errors.confirmPassword.message}</p>
                        )}
                    </div>

                    {/* Terms */}
                    <div className="flex items-start space-x-2">
                        <Checkbox
                            id="acceptTerms"
                            checked={acceptTerms}
                            onCheckedChange={(checked) => setValue("acceptTerms", checked)}
                            disabled={isLoading}
                            className="rounded-none border-primary/40 data-[state=checked]:bg-primary"
                        />
                        <div className="grid gap-1.5 leading-none">
                            <label
                                htmlFor="acceptTerms"
                                className="text-[10px] font-mono uppercase tracking-tight text-muted-foreground cursor-pointer leading-tight"
                            >
                                I agree to the{" "}
                                <Link href="/terms" className="text-primary font-bold hover:underline">
                                    Terms
                                </Link>{" "}
                                and{" "}
                                <Link href="/privacy" className="text-primary font-bold hover:underline">
                                    Privacy Policy
                                </Link>
                            </label>
                            {errors.acceptTerms && (
                                <p className="text-[10px] font-mono text-red-500 uppercase">{errors.acceptTerms.message}</p>
                            )}
                        </div>
                    </div>

                    {/* Submit Button */}
                    <Button type="submit" className="w-full rounded-sm font-mono uppercase tracking-widest text-xs h-11" disabled={isLoading}>
                        {isLoading ? "Signing up..." : "Create Account"}
                    </Button>
                </form>
            </CardContent>

            <CardFooter className="flex justify-center border-t border-border/40 mt-4 pt-4">
                <p className="text-[11px] font-mono text-muted-foreground uppercase tracking-tight">
                    Already have an account?{" "}
                    <Link href="/login" className="text-primary font-bold hover:underline">
                        Log In
                    </Link>
                </p>
            </CardFooter>
        </Card>
    );
}
