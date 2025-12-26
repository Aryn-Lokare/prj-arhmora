// frontend/components/auth/login-form.jsx

"use client";

import { useState } from "react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";

import { useAuth } from "@/components/providers/auth-provider";
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

const loginSchema = z.object({
    email: z.string().email("Please enter a valid email"),
    password: z.string().min(1, "Password is required"),
});

export function LoginForm() {
    const { login } = useAuth();
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);

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
        <Card className="w-full max-w-md tech-card border-t-4 border-t-primary">
            <CardHeader className="space-y-1">
                <div className="flex justify-center mb-4">
                    <div className="px-3 py-1 bg-primary/10 border border-primary/20 rounded-sm">
                        <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-primary font-bold">Secure Access</span>
                    </div>
                </div>
                <CardTitle className="text-2xl font-bold text-center tracking-tight">
                    Sign In
                </CardTitle>
                <CardDescription className="text-center font-mono text-[11px] uppercase tracking-wider">
                    Enter your email and password to continue
                </CardDescription>
            </CardHeader>

            <CardContent>
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                    {/* Error Alert */}
                    {error && (
                        <div className="p-3 text-[12px] font-mono text-red-600 bg-red-50 border border-red-200 rounded-sm">
                            <span className="font-bold mr-2">[ERROR]</span>{error}
                        </div>
                    )}

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
                        <div className="flex items-center justify-between">
                            <Label htmlFor="password" className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Password</Label>
                            <Link
                                href="/forgot-password"
                                className="text-[10px] font-mono uppercase text-primary hover:underline tracking-tighter"
                            >
                                Forgot Password?
                            </Link>
                        </div>
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

                    {/* Submit Button */}
                    <Button type="submit" className="w-full rounded-sm font-mono uppercase tracking-widest text-xs h-11" disabled={isLoading}>
                        {isLoading ? (
                            <span className="flex items-center gap-2">
                                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Signing In...
                            </span>
                        ) : (
                            "Sign In"
                        )}
                    </Button>
                </form>
            </CardContent>

            <CardFooter className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-[9px] font-mono text-muted-foreground uppercase tracking-widest">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                    Direct connection is encrypted and secure
                </div>
                <div className="w-full border-t border-border/40 pt-4 text-center">
                    <p className="text-[11px] font-mono text-muted-foreground uppercase tracking-tight">
                        Don't have an account?{" "}
                        <Link href="/signup" className="text-primary font-bold hover:underline">
                            Create Account
                        </Link>
                    </p>
                </div>
            </CardFooter>
        </Card>
    );
}
