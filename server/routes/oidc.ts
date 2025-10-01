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
    responseTypesSupported: ["code"],
    subjectTypesSupported: ["public", "pairwise"],
    tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
  });

  return c.json(providerService.getDiscoveryDocument());
});
