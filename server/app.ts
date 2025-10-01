import { Hono } from "hono";
import { healthcheckHandler } from "./routes/healthcheck";
import { discoveryHandler } from "./routes/discovery";
import { onError } from "./middleware/on-error";

function createApp() {
  const app = new Hono().basePath("/api");

  app.onError(onError);

  const routes = [healthcheckHandler, discoveryHandler] as const;

  routes.forEach((route) => app.route("/", route));

  return app;
}

const app = createApp();

export default app;
