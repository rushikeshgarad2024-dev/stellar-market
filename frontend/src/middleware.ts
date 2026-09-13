import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PROTECTED_ROUTES = ["/dashboard", "/post-job", "/messages", "/profile"];
const AUTH_ROUTES = ["/auth/login", "/auth/register"];

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";

  const cspHeader = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic' ${isDev ? "'unsafe-eval'" : ""};
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    font-src 'self' https://fonts.gstatic.com;
    img-src 'self' blob: data: https:;
    connect-src 'self' https: wss:;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    object-src 'none';
  `
    .replace(/\s{2,}/g, " ")
    .trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", cspHeader);

  const token = request.cookies.get("stellarmarket_jwt")?.value;
  const { pathname } = request.nextUrl;

  // 1. If user is authenticated and tries to access auth pages, redirect to dashboard
  if (token && AUTH_ROUTES.some((route) => pathname.startsWith(route))) {
    const response = NextResponse.redirect(new URL("/dashboard", request.url));
    response.headers.set("Content-Security-Policy", cspHeader);
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-Content-Type-Options", "nosniff");
    return response;
  }

  // 2. If user is NOT authenticated and tries to access protected pages, redirect to login
  if (!token && PROTECTED_ROUTES.some((route) => pathname.startsWith(route))) {
    const response = NextResponse.redirect(new URL("/auth/login", request.url));
    response.headers.set("Content-Security-Policy", cspHeader);
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-Content-Type-Options", "nosniff");
    return response;
  }

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
  response.headers.set("Content-Security-Policy", cspHeader);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");

  return response;
}

export const config = {
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
