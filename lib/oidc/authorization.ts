import {
  AuthorizationCodePayload,
  AuthorizationRequest,
  CodeChallengeMethodsSupported,
  ResponseTypesSupported,
} from "@/shared/types/oidc";
import { OIDCError } from "./oidc-error";
import { ProviderService } from "./provider-service";
import { ClientService } from "./client-service";
import {
  containsURIFragment,
  getURIProtocol,
  isHTTPS,
  isLocalhostURI,
  isURLValid,
  normalizeSpaceDelimitedSet,
} from "../utils";
import { randomBytes } from "crypto";
import { getRedisClient } from "../redis-client";

export class AuthorizationService {
  constructor(
    private readonly providerService: ProviderService,
    private readonly clientService: ClientService,
  ) {}

  public async validateRequest(authorizationRequest: AuthorizationRequest) {
    const client = await this.validateClient(authorizationRequest.client_id);

    this.validateResponseType(authorizationRequest.response_type, client.responseTypes);
    this.validateScope(authorizationRequest.scope, client.scopes);
    this.validateRedirectUri(authorizationRequest.redirect_uri, client.redirectURIs);
    this.validateState(authorizationRequest.state);
    this.validateResponseMode(authorizationRequest.response_mode, authorizationRequest.response_type);
    this.validateNonce(authorizationRequest.nonce, authorizationRequest.response_type);
    this.validatePrompt(authorizationRequest.prompt);
    this.validatePKCE(authorizationRequest.code_challenge, authorizationRequest.code_challenge_method);
  }

  private async validateClient(clientId: string | undefined) {
    if (!clientId) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "client_id is missing",
        status_code: 400,
      });
    }

    const client = await this.clientService.getClientById(clientId);
    return client;
  }

  private generateCode() {
    return randomBytes(32).toString("base64url");
  }

  public async createAuthorizationCode(payload: AuthorizationCodePayload, ttlSeconds = 600) {
    const code = this.generateCode();
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

  private validateResponseType(responseType: string, allowedResponseTypesForClient: string[]) {
    const responseTypesSupported = this.providerService.responseTypesSupported;

    // Make sure response_type is not missing
    if (!responseType) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing response_type parameter",
        status_code: 400,
      });
    }

    // Detect unsupported response_type
    const normalized = normalizeSpaceDelimitedSet(responseType);
    if (!responseTypesSupported.includes(normalized as ResponseTypesSupported)) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: `response_type must be one of: [${responseTypesSupported.join(", ")}]`,
        status_code: 400,
      });
    }

    const normalizedForClient = allowedResponseTypesForClient.map((rt) => normalizeSpaceDelimitedSet(rt));
    if (!normalizedForClient.includes(normalized)) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: `Client not allowed to use response_type: ${responseType}`,
        status_code: 400,
      });
    }
  }

  private validateScope(scope: string, allowedScopesForClient: string[]) {
    const scopesSupported = this.providerService.scopesSupported as string[];

    if (!scope) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing 'scope' parameter",
        status_code: 400,
      });
    }

    const normalized = normalizeSpaceDelimitedSet(scope);
    const scopes = normalized.split(" ");
    const duplicates = scopes.filter((s, i) => scopes.indexOf(s) !== i);

    // Must contain openid
    if (!scopes.includes("openid")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `The 'scope' parameter must include openid`,
        status_code: 400,
      });
    }

    // Detect duplicates
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Duplicate scope values not allowed: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }

    // Detect unsupported scopes
    const invalid = scopes.filter((s) => !scopesSupported.includes(s));
    if (invalid.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Invalid scope(s): [${invalid.join(", ")}]. Allowed scopes: [${scopesSupported.join(", ")}]`,
        status_code: 400,
      });
    }

    const notAllowedForClient = scopes.filter((scope) => !allowedScopesForClient.includes(scope));
    if (notAllowedForClient.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Client not allowed to request scope(s): [${notAllowedForClient.join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private validateRedirectUri(redirectUri: string | undefined, allowedRedirectUris: string[]) {
    // Case 1: Missing redirect_uri
    if (!redirectUri) {
      if (allowedRedirectUris.length === 1) {
        // If client registered exactly one URI → infer it
        return allowedRedirectUris[0];
      }
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing 'redirect_uri' parameter",
        status_code: 400,
      });
    }

    // Case 2: Reject if URI not valid
    const { fragment, withHash } = containsURIFragment(redirectUri);
    const valid = isURLValid(redirectUri);
    const protocol = getURIProtocol(redirectUri);
    const isHttps = isHTTPS(redirectUri);
    const isLocalhost = isLocalhostURI(redirectUri);

    if (!valid) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "redirect_uri is not a valid URI",
        status_code: 400,
      });
    }

    if (withHash) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `redirect_uri must not contain fragment component - got ${fragment}`,
        status_code: 400,
      });
    }

    if (!(isHttps || (isLocalhost && protocol === "http:"))) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `redirect_uri must use https, except for localhost/loopback`,
        status_code: 400,
      });
    }

    // Case 3: Exact match required
    const normalizedUri = redirectUri.trim();
    if (!allowedRedirectUris.includes(normalizedUri)) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: `redirect_uri not registered for this client: ${normalizedUri}`,
        status_code: 400,
      });
    }
  }

  private validateState(state: string | undefined) {
    // Make sure it is present in the request
    if (!state) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing state parameter",
        status_code: 400,
      });
    }

    // Make sure state is not an empty string
    if (state.trim() === "") {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "state parameter must not be empty",
        status_code: 400,
      });
    }

    // Make sure state does not exceed 1024 characters - to prevent abuse
    if (state.length > 1024) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "state parameter exceeds maximum allowed length (1024 chars)",
        status_code: 400,
      });
    }
  }

  private validateResponseMode(responseMode: string | undefined, responseType: string) {
    if (!responseMode) return;

    // Normalize response_type
    const normalizedResponseType = normalizeSpaceDelimitedSet(responseType);

    if (responseMode === "none") {
      if (normalizedResponseType !== "none") {
        throw new OIDCError({
          error: "invalid_request",
          error_description: "response_mode=none can only be used with response_type=none",
          status_code: 400,
        });
      }
    } else {
      // ensure response mode is supported by the OP
      if (!this.providerService.responseModesSupported?.includes(responseMode as any)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `response_mode '${responseMode}' is not supported`,
          status_code: 400,
        });
      }
    }
  }

  private validateNonce(nonce: string | undefined, responseType: string) {
    const normalizedResponseType = normalizeSpaceDelimitedSet(responseType);

    // Must include nonce if response_type involves id_token
    const requiresNonce = normalizedResponseType.includes("id_token");

    if (requiresNonce) {
      if (!nonce) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: "missing required 'nonce' parameter for response_type including id_token",
          status_code: 400,
        });
      }
    }

    if (nonce) {
      if (nonce.length > 255) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: "'nonce' value is too long",
          status_code: 400,
        });
      }
    }
  }

  private validatePrompt(prompt: string | undefined) {
    if (!prompt) return;

    const validPrompts = ["none", "login", "consent"];
    const prompts = prompt.split(" ");
    const duplicates = prompts.filter((p, i) => prompts.indexOf(p) !== i);

    // Invalid values
    const invalid = prompts.filter((p) => !validPrompts.includes(p));
    if (invalid.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Invalid prompt value(s): [${invalid.join(", ")}]. Allowed: ${validPrompts.join(", ")}`,
        status_code: 400,
      });
    }

    // No duplicates
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Duplicate prompt values not allowed: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }

    // 'none' cannot be combined with others
    if (prompts.includes("none") && prompts.length > 1) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "prompt=none must not be used with other prompt values",
        status_code: 400,
      });
    }
  }

  private validatePKCE(
    codeChallenge: string | undefined,
    codeChallengeMethod: string | undefined,
    // supportedMethods: string[],
  ) {
    // Skip validation if no PKCE params
    if (!codeChallenge) return;

    const supportedMethods = this.providerService.codeChallengeMethodsSupported;

    // Validate code_challenge format (RFC 7636: 43–128 chars, base64url safe)
    const pkceRegex = /^[A-Za-z0-9\-_~.]{43,128}$/;
    if (!pkceRegex.test(codeChallenge)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "invalid code_challenge format. Must be 43 to 128 chars, base64url safe.",
        status_code: 400,
      });
    }

    // Normalize method (default = plain)
    const method = codeChallengeMethod as CodeChallengeMethodsSupported;

    // Ensure method is supported
    if (!supportedMethods?.includes(method)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `unsupported code_challenge_method: ${method}. Supported: [${supportedMethods?.join(", ")}]`,
        status_code: 400,
      });
    }

    // Optional: if you want to forbid "plain" for security reasons
    if (method === "plain" && !supportedMethods.includes("plain")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "code_challenge_method=plain is not allowed",
        status_code: 400,
      });
    }
  }
}
