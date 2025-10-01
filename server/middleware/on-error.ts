import { OIDCError } from "@/lib/oidc/oidc-error";
import { ErrorHandler } from "hono";
import { ContentfulStatusCode } from "hono/utils/http-status";

export const onError: ErrorHandler = (err, c) => {
  const currentStatus = "status" in err ? err.status : c.newResponse(null).status;
  const statusCode = currentStatus !== 200 ? (currentStatus as ContentfulStatusCode) : 500;

  if (err instanceof OIDCError) {
    return c.json(err, err.status_code as ContentfulStatusCode);
  }

  if (err instanceof Error) {
    return c.json({ ...err, stack: process.env.NODE_ENV === "production" ? undefined : err.stack }, 500);
  }

  return c.json(
    {
      name: "Error",
      message: "Something went wrong!",
    },
    statusCode,
  );
};
