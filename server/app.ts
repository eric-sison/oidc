import { Hono } from "hono";
import { healthcheckHandler } from "./routes/healthcheck";
import { onError } from "./middleware/on-error";
import { ProviderInstance } from "@/lib/oidc/oidc-instance";
import { oidcHandler } from "./routes/oidc";
import { auth } from "@/lib/auth";
import { cors } from "hono/cors";

export const $oidc = ProviderInstance.init();

function createApp() {
  const app = new Hono().basePath("/api");

  app.onError(onError);

  /**
   * Mount better-auth handlers into our Hono app.
   * See: https://www.better-auth.com/docs/integrations/hono
   * There’s no need to include `/api` because it’s already set as the base path.
   */
  app.on(["POST", "GET", "OPTIONS"], "/auth/**", (c) => auth.handler(c.req.raw));

  app.use(cors());

  // Validate oidc configuration first
  app.use("/oidc/.well-known/*", async (_, next) => {
    $oidc.provider.validateConfig();
    return await next();
  });

  const routes = [
    // list of route handlers...
    healthcheckHandler,
    oidcHandler,
  ] as const;

  routes.forEach((route) => app.route("/", route));

  return app;
}

const app = createApp();

export default app;
