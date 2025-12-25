// frontend/middleware.js

import { NextResponse } from 'next/server';

const protectedRoutes = ['/dashboard', '/profile', '/settings'];

const authRoutes = [
    '/login',
    '/signup',
    '/forgot-password',
    '/reset-password',
    '/verify-email',
    '/resend-verification',
];

export function middleware(request) {
    const { pathname } = request.nextUrl;
    const accessToken = request.cookies.get('access_token')?.value;
    const isAuthenticated = !!accessToken;

    // Protected routes - require auth
    const isProtectedRoute = protectedRoutes.some(route =>
        pathname.startsWith(route)
    );

    if (isProtectedRoute && !isAuthenticated) {
        const loginUrl = new URL('/login', request.url);
        loginUrl.searchParams.set('callbackUrl', pathname);
        return NextResponse.redirect(loginUrl);
    }

    // Auth routes - redirect if already logged in (except verify-email and reset-password)
    const isAuthRoute = authRoutes.some(route => pathname.startsWith(route));
    const allowWhenAuthenticated = ['/verify-email', '/reset-password'];
    const shouldRedirect = !allowWhenAuthenticated.some(route => pathname.startsWith(route));

    if (isAuthRoute && isAuthenticated && shouldRedirect) {
        return NextResponse.redirect(new URL('/dashboard', request.url));
    }

    return NextResponse.next();
}

export const config = {
    matcher: ['/((?!api|_next/static|_next/image|favicon.ico|public).*)'],
};
