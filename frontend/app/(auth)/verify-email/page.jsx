// frontend/app/(auth)/verify-email/page.jsx

"use client";

import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { authService } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

export default function VerifyEmailPage() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const token = searchParams.get("token");

    const [status, setStatus] = useState("loading"); // loading, success, error, no-token
    const [message, setMessage] = useState("");

    useEffect(() => {
        if (!token) {
            setStatus("no-token");
            setMessage("No verification token provided.");
            return;
        }

        const verifyEmail = async () => {
            try {
                const response = await authService.verifyEmail(token);
                if (response.success) {
                    setStatus("success");
                    setMessage(response.message);
                } else {
                    setStatus("error");
                    setMessage(response.message);
                }
            } catch (error) {
                setStatus("error");
                setMessage(
                    error.response?.data?.message || "Failed to verify email. Please try again."
                );
            }
        };

        verifyEmail();
    }, [token]);

    const renderContent = () => {
        switch (status) {
            case "loading":
                return (
                    <>
                        <div className="flex justify-center mb-6">
                            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-primary"></div>
                        </div>
                        <CardTitle className="text-2xl text-center">Verifying your email...</CardTitle>
                        <CardDescription className="text-center mt-2">
                            Please wait while we verify your email address.
                        </CardDescription>
                    </>
                );

            case "success":
                return (
                    <>
                        <div className="flex justify-center mb-6">
                            <div className="h-16 w-16 rounded-full bg-green-100 flex items-center justify-center">
                                <svg
                                    className="h-8 w-8 text-green-600"
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
                        <CardTitle className="text-2xl text-center text-green-600">
                            Email Verified!
                        </CardTitle>
                        <CardDescription className="text-center mt-2">
                            {message}
                        </CardDescription>
                    </>
                );

            case "error":
                return (
                    <>
                        <div className="flex justify-center mb-6">
                            <div className="h-16 w-16 rounded-full bg-red-100 flex items-center justify-center">
                                <svg
                                    className="h-8 w-8 text-red-600"
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
                        <CardTitle className="text-2xl text-center text-red-600">
                            Verification Failed
                        </CardTitle>
                        <CardDescription className="text-center mt-2">
                            {message}
                        </CardDescription>
                    </>
                );

            case "no-token":
                return (
                    <>
                        <div className="flex justify-center mb-6">
                            <div className="h-16 w-16 rounded-full bg-yellow-100 flex items-center justify-center">
                                <svg
                                    className="h-8 w-8 text-yellow-600"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth={2}
                                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                                    />
                                </svg>
                            </div>
                        </div>
                        <CardTitle className="text-2xl text-center text-yellow-600">
                            Invalid Link
                        </CardTitle>
                        <CardDescription className="text-center mt-2">
                            {message}
                        </CardDescription>
                    </>
                );

            default:
                return null;
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <Card className="w-full max-w-md">
                <CardHeader>{renderContent()}</CardHeader>

                <CardContent>
                    {status === "success" && (
                        <Button
                            className="w-full"
                            onClick={() => router.push("/login")}
                        >
                            Continue to Login
                        </Button>
                    )}

                    {status === "error" && (
                        <div className="space-y-4">
                            <Button
                                className="w-full"
                                variant="outline"
                                onClick={() => router.push("/resend-verification")}
                            >
                                Resend Verification Email
                            </Button>
                            <Button
                                className="w-full"
                                onClick={() => router.push("/login")}
                            >
                                Go to Login
                            </Button>
                        </div>
                    )}

                    {status === "no-token" && (
                        <Button
                            className="w-full"
                            onClick={() => router.push("/login")}
                        >
                            Go to Login
                        </Button>
                    )}
                </CardContent>

                <CardFooter className="flex justify-center">
                    <p className="text-sm text-gray-600">
                        Need help?{" "}
                        <Link href="/contact" className="text-primary hover:underline">
                            Contact Support
                        </Link>
                    </p>
                </CardFooter>
            </Card>
        </div>
    );
}
