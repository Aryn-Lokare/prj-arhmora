// frontend/app/(protected)/dashboard/page.jsx

"use client";

import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

export default function DashboardPage() {
    const { user, logout, loading } = useAuth();

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-50 p-8">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold">Dashboard</h1>
                        <p className="text-gray-600">Welcome back, {user?.first_name}!</p>
                    </div>
                    <Button variant="outline" onClick={logout}>
                        Logout
                    </Button>
                </div>

                {/* User Info Card */}
                <Card className="mb-8">
                    <CardHeader>
                        <CardTitle>Profile Information</CardTitle>
                        <CardDescription>Your account details</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <p className="text-sm text-gray-500">Name</p>
                                <p className="font-medium">
                                    {user?.first_name} {user?.last_name}
                                </p>
                            </div>
                            <div>
                                <p className="text-sm text-gray-500">Email</p>
                                <p className="font-medium">{user?.email}</p>
                            </div>
                            <div>
                                <p className="text-sm text-gray-500">Username</p>
                                <p className="font-medium">{user?.username}</p>
                            </div>
                            <div>
                                <p className="text-sm text-gray-500">Member Since</p>
                                <p className="font-medium">
                                    {new Date(user?.date_joined).toLocaleDateString()}
                                </p>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Quick Actions */}
                <div className="grid md:grid-cols-3 gap-6">
                    <Card className="cursor-pointer hover:shadow-lg transition-shadow">
                        <CardHeader>
                            <CardTitle className="text-lg">Edit Profile</CardTitle>
                            <CardDescription>Update your information</CardDescription>
                        </CardHeader>
                    </Card>

                    <Card className="cursor-pointer hover:shadow-lg transition-shadow">
                        <CardHeader>
                            <CardTitle className="text-lg">Change Password</CardTitle>
                            <CardDescription>Update your password</CardDescription>
                        </CardHeader>
                    </Card>

                    <Card className="cursor-pointer hover:shadow-lg transition-shadow">
                        <CardHeader>
                            <CardTitle className="text-lg">Settings</CardTitle>
                            <CardDescription>Manage preferences</CardDescription>
                        </CardHeader>
                    </Card>
                </div>
            </div>
        </div>
    );
}