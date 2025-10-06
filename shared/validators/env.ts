import z from "zod";

// zod validation schemas
export const EnvSchema = z.object({
  // Add environment variables here...
  BETTER_AUTH_URL: z.url(),
  BETTER_AUTH_SECRET: z.string(),
  CALLBACK_URL: z.url(),
  CLIENT_ID: z.uuid(),
  DB_HOST: z.string(),
  DB_PORT: z.coerce.number(),
  DB_USER: z.string(),
  DB_PASS: z.string(),
  DB_NAME: z.string(),
  REDIS_HOST: z.string(),
  REDIS_PORT: z.coerce.number(),
});

export type Env = z.infer<typeof EnvSchema>;
