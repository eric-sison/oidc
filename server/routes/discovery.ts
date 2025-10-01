import { ProviderService } from "@/lib/oidc/provider-service";
import { Hono } from "hono";

export const discoveryHandler = new Hono()
  .basePath("/oidc/.well-known/openid-configuration")
  .get("/", async (c) => {
    const providerService = new ProviderService({
      issuer: "http://localhost:3000",
      authorizationEndpoint: "http://localhost:3000/api/oidc/authorize",
      jwksUri: "http://localhost:3000/api/oidc/.well-known/jwks.json",
      tokenEndpoint: "http://localhost:3000/api/oidc/token",
      userinfoEndpoint: "http://localhost:3000/oidc/userinfo",
      idTokenSigningAlgValuesSupported: ["RS256"],
      grantTypesSupported: ["authorization_code"],
      scopesSupported: ["address", "openid"],
      responseTypesSupported: ["code"],
      subjectTypesSupported: ["pairwise", "public"],
      tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
      claimsSupported: ["address", "sub"],
      codeChallengeMethodsSupported: ["S256"],
    });

    return c.json(providerService.getDiscoveryDocument());
  });
