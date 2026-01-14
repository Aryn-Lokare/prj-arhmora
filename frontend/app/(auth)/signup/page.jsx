// frontend/app/(auth)/signup/page.jsx

import { SignupForm } from "@/components/auth/signup-form";

export const metadata = {
    title: "Sign Up",
    description: "Create a new account",
};

export default function SignupPage() {
    return (
        <div className="h-screen w-full flex flex-col items-center justify-center bg-white p-4 overflow-hidden">
            <SignupForm />
        </div>
    );
}
