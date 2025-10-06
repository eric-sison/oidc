import { AuthorizationCodePayload, AuthorizationRequest } from "@/shared/types/oidc";
import { randomBytes } from "crypto";
import { getRedisClient } from "../redis-client";
import { AuthorizationValidatorService } from "./authorization-validator";

export class AuthorizationService {
  constructor(private readonly authorizationValidator: AuthorizationValidatorService) {}

  public async validateRequest(authorizationRequest: AuthorizationRequest) {
    await this.authorizationValidator.validateRequest(authorizationRequest);
  }

  public async createAuthorizationCode(payload: AuthorizationCodePayload, ttlSeconds = 600) {
    const code = randomBytes(32).toString("base64url");
    const redisClient = await getRedisClient();
    await redisClient.connect();

    await redisClient.set(`auth_code:${code}`, JSON.stringify(payload), {
      expiration: {
        type: "EX",
        value: ttlSeconds,
      },
    });

    redisClient.destroy();

    return code;
  }

  public async consumeAuthorizationCode(code: string): Promise<AuthorizationCodePayload | null> {
    const key = `auth_code:${code}`;
    const redisClient = await getRedisClient();
    await redisClient.connect();

    const data = await redisClient.get(key);

    if (!data) {
      return null; // invalid or expired
    }

    // Delete immediately → single use
    await redisClient.del(key);
    redisClient.destroy();

    return JSON.parse(data) as AuthorizationCodePayload;
  }
}
