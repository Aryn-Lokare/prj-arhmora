// frontend/components/auth/google-login-button.jsx

"use client";

import { useGoogleLogin, GoogleLogin } from "@react-oauth/google";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { authService } from "@/lib/auth";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";

// Option 1: Using Google's Default Button
export function GoogleLoginButton({ onSuccess, onError }) {
    const router = useRouter();
    const { refreshUser } = useAuth();
    const [isLoading, setIsLoading] = useState(false);

    const handleSuccess = async (credentialResponse) => {
        setIsLoading(true);
        try {
            const response = await authService.googleAuth(credentialResponse.credential);

            if (response.success) {
                await refreshUser();
                onSuccess?.(response);
                router.push("/dashboard");
            } else {
                onError?.(response.message);
            }
        } catch (error) {
            console.error("Google login error:", error);
            onError?.(error.response?.data?.message || "Google login failed");
        } finally {
            setIsLoading(false);
        }
    };

    const handleError = () => {
        onError?.("Google login was cancelled or failed");
    };

    return (
        <div className="w-full flex justify-center">
            <GoogleLogin
                onSuccess={handleSuccess}
                onError={handleError}
                useOneTap
                use_fedcm_for_prompt={true}
                theme="outline"
                size="large"
                text="continue_with"
                shape="rectangular"
                width="100%"
            />
        </div>
    );
}

// Option 2: Custom Styled Button
export function CustomGoogleLoginButton({ onSuccess, onError }) {
    const router = useRouter();
    const { refreshUser } = useAuth();
    const [isLoading, setIsLoading] = useState(false);

    const login = useGoogleLogin({
        onSuccess: async (tokenResponse) => {
            setIsLoading(true);
            try {
                // Get user info from Google
                const userInfoResponse = await fetch(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    {
                        headers: {
                            Authorization: `Bearer ${tokenResponse.access_token}`,
                        },
                    }
                );

                if (!userInfoResponse.ok) {
                    throw new Error("Failed to get user info from Google");
                }

                // For this approach, we need to use a different flow
                // This sends the access_token which needs different handling on backend
                // The simpler approach is using the credential (ID token) from GoogleLogin

                // Note: This approach requires additional backend handling
                // For simplicity, use GoogleLoginButton above which uses the credential/ID token

            } catch (error) {
                console.error("Google login error:", error);
                onError?.(error.message || "Google login failed");
            } finally {
                setIsLoading(false);
            }
        },
        onError: () => {
            onError?.("Google login was cancelled or failed");
        },
    });

    return (
        <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={() => login()}
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
                    Connecting...
                </span>
            ) : (
                <span className="flex items-center gap-2">
                    <svg className="h-5 w-5" viewBox="0 0 24 24">
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
                    Continue with Google
                </span>
            )}
        </Button>
    );
}