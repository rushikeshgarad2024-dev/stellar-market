import { NextRequest } from "next/server";
import { middleware } from "../middleware";

describe("Security Headers & CSP Middleware", () => {
  it("injects Content-Security-Policy with nonce and security headers on standard requests", () => {
    const request = new NextRequest("http://localhost:3000/");
    const response = middleware(request);

    const csp = response.headers.get("Content-Security-Policy");
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);

    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("injects CSP and security headers on unauthenticated redirect for protected route", () => {
    const request = new NextRequest("http://localhost:3000/dashboard");
    const response = middleware(request);

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("http://localhost:3000/auth/login");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("injects CSP and security headers on authenticated redirect for auth route", () => {
    const request = new NextRequest("http://localhost:3000/auth/login", {
      headers: {
        cookie: "stellarmarket_jwt=mock-valid-jwt-token",
      },
    });
    const response = middleware(request);

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("http://localhost:3000/dashboard");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});
