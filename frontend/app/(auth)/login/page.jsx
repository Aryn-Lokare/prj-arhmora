// frontend/app/(auth)/login/page.jsx

import { LoginForm } from "@/components/auth/login-form";

export const metadata = {
    title: "Login",
    description: "Login to your account",
};

export default function LoginPage() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <LoginForm />
        </div>
    );
}