import { Hono } from "hono";
import { $oidc } from "../app";
import { AuthorizationRequest } from "@/shared/types/oidc";
import { createEnv } from "@/helpers/createEnv";
import { auth } from "@/lib/auth";

export const oidcHandler = new Hono()
  .basePath("/oidc")

  // Discovery document
  .get("/.well-known/openid-configuration", async (c) => {
    const discovery = $oidc.provider.getDiscoveryDocument();
    return c.json(discovery);
  })

  // Jwks uri
  .get("/.well-known/jwks.json", async (c) => {
    return c.json({ jwks: "here" });
  })

  // Authorization
  .get("/authorize", async (c) => {
    // Intialize environment variables
    const env = createEnv();

    // Extract authorization request from query params
    const authorizationRequest = c.req.query() as AuthorizationRequest;

    // Validate the authorization request according to rules set
    await $oidc.authorization.validateRequest(authorizationRequest);

    // Extract current session
    const session = await auth.api.getSession({ headers: c.req.raw.headers });

    // If there is no session, redirect to login page with the same set of parameters
    if (!session) {
      // Initialize the redirect url for login
      const url = new URL(`${env.BETTER_AUTH_URL}/auth/login`);

      // Build the search params in the url
      const searchParams = new URLSearchParams(authorizationRequest);

      // Append the search params to the login url
      url.search = searchParams.toString();

      // Redirect to login page
      return c.redirect(url);
    }

    const clientRedirect = await $oidc.flow.initiateFlow(authorizationRequest, session.user.id);
    return c.redirect(clientRedirect);
  })
  .get("/callback", async (c) => {
    const searchParams = c.req.query();
    return c.json(searchParams);
  });
