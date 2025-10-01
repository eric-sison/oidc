import { ProviderService } from "@/lib/oidc/provider-service";
import { Hono } from "hono";

export const oidcHandler = new Hono().basePath("/oidc").get("/", async (c) => {
  const providerService = new ProviderService({
    issuer: "http://localhost:3000",
    authorizationEndpoint: "http://localhost:3000/api/oidc/authorize",
    jwksUri: "http://localhost:3000/api/oidc/.well-known/jwks.json",
    tokenEndpoint: "http://localhost:3000/api/oidc/token",
    userinfoEndpoint: "http://localhost:3000/oidc/userinfo",
    idTokenSigningAlgValuesSupported: ["RS256"],
    // responseModesSupported: ["form_post"],
    grantTypesSupported: ["authorization_code"],
    scopesSupported: ["address", "email", "openid"],
    responseTypesSupported: ["code", "id_token code"],
    subjectTypesSupported: ["pairwise", "public"],
    tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
    claimsSupported: ["address", "sub"],
    codeChallengeMethodsSupported: ["S256"],
  });

  return c.json(providerService.getDiscoveryDocument());
});
