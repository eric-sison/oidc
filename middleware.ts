import { type NextRequest, NextResponse } from "next/server";
import { auth } from "./lib/auth";
import { createEnv } from "./helpers/createEnv";
import {
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  Configuration,
  discovery,
  randomPKCECodeVerifier,
  randomState,
} from "openid-client";

const publicRoutes = ["/auth"];

export async function middleware(request: NextRequest) {
  const env = createEnv();
  const { pathname } = request.nextUrl;

  // Check session (for protected routes)
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  const hasSession = !!session;

  // Prevent logged-in users from accessing /auth/*
  if (publicRoutes.some(() => pathname.startsWith("/auth"))) {
    if (hasSession) {
      // redirect authenticated users away from auth pages
      return NextResponse.redirect(new URL("/", request.url));
    }
    return NextResponse.next();
  }

  // Protect all other routes: redirect to login if no session
  if (!hasSession) {
    // Allow access if the pathname is one of the public routes
    if (publicRoutes.some((route) => pathname.startsWith(route))) {
      return NextResponse.next();
    }

    const serverURL = new URL(`${env.BETTER_AUTH_URL}/api/oidc/.well-known/openid-configuration`);
    const clientId = env.CLIENT_ID;
    const redirectURI = env.CALLBACK_URL;
    const scope = "openid profile email";
    const state = randomState();
    const codeVerifier = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);

    const parameters = {
      redirect_uri: redirectURI,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      response_mode: "query",
    };

    const config: Configuration = await discovery(serverURL, clientId);
    const redirectTo: URL = buildAuthorizationUrl(config, parameters);

    return NextResponse.redirect(redirectTo);
  }

  return NextResponse.next();
}

export const config = {
  runtime: "nodejs",
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt|.*\\.(?:svg|png|jpg|jpeg|webp|gif|ico|ttf|woff|woff2|eot)).*)",
  ],
};
