// frontend/app/(auth)/signup/page.jsx

import { SignupForm } from "@/components/auth/signup-form";

export const metadata = {
    title: "Sign Up",
    description: "Create a new account",
};

export default function SignupPage() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <SignupForm />
        </div>
    );
}
