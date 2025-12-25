// frontend/components/providers/auth-provider.jsx

"use client";

import { createContext, useContext, useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { authService } from "@/lib/auth";

const AuthContext = createContext(undefined);

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    const fetchUser = useCallback(async () => {
        try {
            if (!authService.isAuthenticated()) {
                setUser(null);
                setLoading(false);
                return;
            }

            const response = await authService.getUser();
            if (response.success) {
                setUser(response.data);
            } else {
                setUser(null);
            }
        } catch (error) {
            console.error("Error fetching user:", error);
            setUser(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchUser();
    }, [fetchUser]);

    const register = async (data) => {
        const response = await authService.register(data);
        if (response.success) {
            setUser(response.data.user);
            router.push("/dashboard");
        }
        return response;
    };

    const login = async (email, password) => {
        const response = await authService.login(email, password);
        if (response.success) {
            setUser(response.data.user);
            router.push("/dashboard");
        }
        return response;
    };

    const logout = async () => {
        await authService.logout();
        setUser(null);
        router.push("/login");
    };

    const updateUser = async (data) => {
        const response = await authService.updateUser(data);
        if (response.success) {
            setUser(response.data);
        }
        return response;
    };

    // Refresh user data (useful after Google login)
    const refreshUser = async () => {
        try {
            const response = await authService.getUser();
            if (response.success) {
                setUser(response.data);
            }
        } catch (error) {
            console.error("Error refreshing user:", error);
        }
    };

    const value = {
        user,
        loading,
        isAuthenticated: !!user,
        login,
        logout,
        register,
        updateUser,
        refreshUser,
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
}