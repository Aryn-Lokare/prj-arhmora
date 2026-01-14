// frontend/app/(auth)/login/page.jsx

import { LoginForm } from "@/components/auth/login-form";

export const metadata = {
    title: "Login",
    description: "Login to your account",
};

export default function LoginPage() {
    return (
        <div className="h-screen w-full flex flex-col items-center justify-center bg-white p-4 overflow-hidden">
            <LoginForm />
        </div>
    );
}