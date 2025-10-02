import { Hono } from "hono";
import { $oidc } from "../app";
import { AuthorizationRequest } from "@/shared/types/oidc";

export const oidcHandler = new Hono()
  .basePath("/oidc")

  // Discovery document
  .get("/.well-known/openid-configuration", async (c) => {
    const discovery = $oidc.getProvider().getDiscoveryDocument();
    return c.json(discovery);
  })

  // Jwks uri
  .get("/.well-known/jwks.json", async (c) => {
    return c.json({ jwks: "here" });
  })

  // Authorization
  .get("/authorize", async (c) => {
    const authorizationRequest = c.req.query() as AuthorizationRequest;
    await $oidc.getAuthorization().validateRequest(authorizationRequest);
    return c.json({ test: "hehe" });
  });
