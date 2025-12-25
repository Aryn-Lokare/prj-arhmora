// frontend/components/settings/social-accounts.jsx

"use client";

import { useState, useEffect } from "react";
import { authService } from "@/lib/auth";
import { GoogleLoginButton } from "@/components/auth/google-login-button";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

export function SocialAccounts() {
    const [accounts, setAccounts] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState("");
    const [successMessage, setSuccessMessage] = useState("");

    useEffect(() => {
        fetchSocialAccounts();
    }, []);

    const fetchSocialAccounts = async () => {
        try {
            const response = await authService.getSocialAccounts();
            if (response.success) {
                setAccounts(response.data);
            }
        } catch (err) {
            console.error("Error fetching social accounts:", err);
        } finally {
            setIsLoading(false);
        }
    };

    const handleDisconnect = async (provider) => {
        try {
            const response = await authService.disconnectSocialAccount(provider);
            if (response.success) {
                setSuccessMessage(response.message);
                fetchSocialAccounts();
                setTimeout(() => setSuccessMessage(""), 3000);
            } else {
                setError(response.message);
                setTimeout(() => setError(""), 3000);
            }
        } catch (err) {
            setError(err.response?.data?.message || "Failed to disconnect account");
            setTimeout(() => setError(""), 3000);
        }
    };

    const handleGoogleSuccess = () => {
        fetchSocialAccounts();
        setSuccessMessage("Google account connected successfully");
        setTimeout(() => setSuccessMessage(""), 3000);
    };

    const isConnected = (provider) => {
        return accounts.some((acc) => acc.provider === provider);
    };

    if (isLoading) {
        return (
            <Card>
                <CardContent className="py-8 text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle>Connected Accounts</CardTitle>
                <CardDescription>
                    Manage your connected social accounts
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                {/* Messages */}
                {error && (
                    <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg">
                        {error}
                    </div>
                )}
                {successMessage && (
                    <div className="p-3 text-sm text-green-600 bg-green-50 border border-green-200 rounded-lg">
                        {successMessage}
                    </div>
                )}

                {/* Google Account */}
                <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-3">
                        <svg className="h-6 w-6" viewBox="0 0 24 24">
                            <path
                                fill="#4285F4"
                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                            />
                            <path
                                fill="#34A853"
                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                            />
                            <path
                                fill="#FBBC05"
                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                            />
                            <path
                                fill="#EA4335"
                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                            />
                        </svg>
                        <div>
                            <p className="font-medium">Google</p>
                            <p className="text-sm text-gray-500">
                                {isConnected("google") ? "Connected" : "Not connected"}
                            </p>
                        </div>
                    </div>

                    {isConnected("google") ? (
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDisconnect("google")}
                        >
                            Disconnect
                        </Button>
                    ) : (
                        <div className="w-32">
                            <GoogleLoginButton
                                onSuccess={handleGoogleSuccess}
                                onError={(msg) => setError(msg)}
                            />
                        </div>
                    )}
                </div>

                {/* Info Text */}
                <p className="text-sm text-gray-500">
                    Connect social accounts for quick and easy sign-in. You can disconnect them at any time.
                </p>
            </CardContent>
        </Card>
    );
}