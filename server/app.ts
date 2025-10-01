import { Hono } from "hono";
import { healthcheckHandler } from "./routes/healthcheck";
import { oidcHandler } from "./routes/oidc";
import { onError } from "./middleware/on-error";

function createApp() {
  const app = new Hono().basePath("/api");

  app.onError(onError);

  const routes = [healthcheckHandler, oidcHandler] as const;

  routes.forEach((route) => app.route("/", route));

  return app;
}

const app = createApp();

export default app;
