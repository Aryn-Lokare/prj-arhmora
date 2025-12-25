// frontend/lib/auth.js

import api from './api';
import Cookies from 'js-cookie';

export const authService = {
    // Register new user
    async register(data) {
        const response = await api.post('/auth/register/', {
            email: data.email,
            password: data.password,
            password2: data.confirmPassword,
            first_name: data.firstName,
            last_name: data.lastName,
        });

        if (response.data.success) {
            const { tokens } = response.data.data;
            this.setTokens(tokens);
        }

        return response.data;
    },

    // Login user
    async login(email, password) {
        const response = await api.post('/auth/login/', { email, password });

        if (response.data.success) {
            const { tokens } = response.data.data;
            this.setTokens(tokens);
        }

        return response.data;
    },

    // Logout user
    async logout() {
        try {
            const refreshToken = Cookies.get('refresh_token');
            await api.post('/auth/logout/', { refresh: refreshToken });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearTokens();
        }
    },

    // Get current user
    async getUser() {
        const response = await api.get('/auth/user/');
        return response.data;
    },

    // Update user profile
    async updateUser(data) {
        const response = await api.patch('/auth/user/', data);
        return response.data;
    },

    // Change password
    async changePassword(oldPassword, newPassword, newPassword2) {
        const response = await api.post('/auth/change-password/', {
            old_password: oldPassword,
            new_password: newPassword,
            new_password2: newPassword2,
        });
        return response.data;
    },

    // Email Verification
    async verifyEmail(token) {
        const response = await api.post('/auth/verify-email/', { token });
        return response.data;
    },

    async resendVerificationEmail(email) {
        const response = await api.post('/auth/resend-verification/', { email });
        return response.data;
    },

    // Password Reset
    async forgotPassword(email) {
        const response = await api.post('/auth/forgot-password/', { email });
        return response.data;
    },

    async validateResetToken(token) {
        const response = await api.post('/auth/validate-reset-token/', { token });
        return response.data;
    },

    async resetPassword(token, password, password2) {
        const response = await api.post('/auth/reset-password/', {
            token,
            password,
            password2,
        });
        return response.data;
    },

    // ============================================
    // GOOGLE AUTH
    // ============================================

    async googleAuth(credential) {
        const response = await api.post('/auth/google/', { credential });

        if (response.data.success) {
            const { tokens } = response.data.data;
            this.setTokens(tokens);
        }

        return response.data;
    },

    // Get connected social accounts
    async getSocialAccounts() {
        const response = await api.get('/auth/social-accounts/');
        return response.data;
    },

    // Disconnect social account
    async disconnectSocialAccount(provider) {
        const response = await api.post(`/auth/social-accounts/${provider}/disconnect/`);
        return response.data;
    },

    // ============================================
    // TOKEN HELPERS
    // ============================================

    setTokens(tokens) {
        Cookies.set('access_token', tokens.access, {
            expires: 1,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        Cookies.set('refresh_token', tokens.refresh, {
            expires: 7,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
    },

    clearTokens() {
        Cookies.remove('access_token');
        Cookies.remove('refresh_token');
    },

    isAuthenticated() {
        return !!Cookies.get('access_token');
    },

    getAccessToken() {
        return Cookies.get('access_token');
    },
};