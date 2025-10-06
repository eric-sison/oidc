import { createEnv } from "@/helpers/createEnv";
import { createClient } from "redis";

const env = createEnv();

export const getRedisClient = async () => {
  const client = createClient({
    socket: {
      host: process.env.NODE_ENV === "development" ? env.REDIS_HOST : "cache",
      port: process.env.NODE_ENV === "development" ? env.REDIS_PORT : 6379,
    },
  });

  client.on("error", (err) => console.error("Redis Client Error", err));

  return client;
};
