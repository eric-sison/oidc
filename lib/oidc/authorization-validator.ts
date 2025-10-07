import { OIDCError } from "./oidc-error";
import { ProviderService } from "./provider-service";
import { ClientService } from "./client-service";
import {
  AuthorizationRequest,
  CodeChallengeMethodsSupported,
  ResponseModesSupported,
  ResponseTypesSupported,
} from "@/shared/types/oidc";
import {
  containsURIFragment,
  getURIProtocol,
  isHTTPS,
  isLocalhostURI,
  isURLValid,
  normalizeSpaceDelimitedSet,
} from "../utils";

const CONSTANTS = {
  AUTH_CODE_TTL_SECONDS: 600,
  AUTH_CODE_BYTES: 32,
  STATE_MAX_LENGTH: 1024,
  NONCE_MAX_LENGTH: 255,
  PKCE_REGEX: /^[A-Za-z0-9\-_~.]{43,128}$/,
  VALID_PROMPTS: ["none", "login", "consent"] as const,
} as const;

export class AuthorizationValidatorService {
  constructor(
    private readonly providerService: ProviderService,
    private readonly clientService: ClientService,
  ) {}

  public async validateRequest(authorizationRequest: AuthorizationRequest) {
    const {
      client_id,
      response_type,
      scope,
      redirect_uri,
      state,
      response_mode,
      nonce,
      prompt,
      code_challenge,
      code_challenge_method,
    } = authorizationRequest;

    const client = await this.validateClient(client_id);

    this.validateResponseType(response_type, client.responseTypes);
    this.validateScope(scope, client.scopes);
    this.validateRedirectUri(redirect_uri, client.redirectURIs);
    this.validateState(state);
    this.validateResponseMode(response_mode, response_type);
    this.validateNonce(nonce, response_type);
    this.validatePrompt(prompt);
    this.validatePKCE(code_challenge, code_challenge_method);
  }

  // ========== Validation Methods ==========

  private async validateClient(clientId: string | undefined) {
    if (!clientId) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "client_id is missing",
        status_code: 400,
      });
    }

    const client = await this.clientService.getClientById(clientId);

    if (!client.isActive) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: "Client is no longer active",
        status_code: 400,
      });
    }

    return client;
  }

  private validateResponseType(responseType: string, allowedResponseTypesForClient: string[]): void {
    if (!responseType) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing response_type parameter",
        status_code: 400,
      });
    }

    const normalized = normalizeSpaceDelimitedSet(responseType);
    const responseTypesSupported = this.providerService.responseTypesSupported;

    if (!responseTypesSupported.includes(normalized as ResponseTypesSupported)) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: `response_type must be one of: [${responseTypesSupported.join(", ")}]`,
        status_code: 400,
      });
    }

    const normalizedForClient = allowedResponseTypesForClient.map(normalizeSpaceDelimitedSet);
    if (!normalizedForClient.includes(normalized)) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: `Client not allowed to use response_type: ${responseType}`,
        status_code: 400,
      });
    }
  }

  private validateScope(scope: string, allowedScopesForClient: string[]): void {
    if (!scope) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing 'scope' parameter",
        status_code: 400,
      });
    }

    const normalized = normalizeSpaceDelimitedSet(scope);
    const scopes = normalized.split(" ");

    this.checkForDuplicates(scopes, "scope");
    this.requireOpenIdScope(scopes);
    this.checkUnsupportedScopes(scopes);
    this.checkClientScopePermissions(scopes, allowedScopesForClient);
  }

  private requireOpenIdScope(scopes: string[]): void {
    if (!scopes.includes("openid")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: "The 'scope' parameter must include openid",
        status_code: 400,
      });
    }
  }

  private checkUnsupportedScopes(scopes: string[]): void {
    const scopesSupported = this.providerService.scopesSupported as string[];
    const invalid = scopes.filter((s) => !scopesSupported.includes(s));

    if (invalid.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Invalid scope(s): [${invalid.join(", ")}]. Allowed scopes: [${scopesSupported.join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private checkClientScopePermissions(scopes: string[], allowedScopesForClient: string[]): void {
    const notAllowedForClient = scopes.filter((scope) => !allowedScopesForClient.includes(scope));

    if (notAllowedForClient.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Client not allowed to request scope(s): [${notAllowedForClient.join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private validateRedirectUri(redirectUri: string | undefined, allowedRedirectURIsForClient: string[]): void {
    if (!redirectUri) {
      this.handleMissingRedirectUri(allowedRedirectURIsForClient);
      return;
    }

    this.checkRedirectUriValidity(redirectUri);
    this.checkRedirectUriRegistration(redirectUri, allowedRedirectURIsForClient);
  }

  private handleMissingRedirectUri(allowedRedirectUris: string[]): void {
    if (allowedRedirectUris.length !== 1) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing 'redirect_uri' parameter",
        status_code: 400,
      });
    }
  }

  private checkRedirectUriValidity(redirectUri: string): void {
    if (!isURLValid(redirectUri)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "redirect_uri is not a valid URI",
        status_code: 400,
      });
    }

    const { fragment, withHash } = containsURIFragment(redirectUri);
    if (withHash) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `redirect_uri must not contain fragment component - got ${fragment}`,
        status_code: 400,
      });
    }

    const protocol = getURIProtocol(redirectUri);
    const isHttps = isHTTPS(redirectUri);
    const isLocalhost = isLocalhostURI(redirectUri);

    if (!(isHttps || (isLocalhost && protocol === "http:"))) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "redirect_uri must use https, except for localhost/loopback",
        status_code: 400,
      });
    }
  }

  private checkRedirectUriRegistration(redirectUri: string, allowedRedirectUris: string[]): void {
    const normalizedUri = redirectUri.trim();
    if (!allowedRedirectUris.includes(normalizedUri)) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: `redirect_uri not registered for this client: ${normalizedUri}`,
        status_code: 400,
      });
    }
  }

  private validateState(state: string | undefined): void {
    if (!state) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing state parameter",
        status_code: 400,
      });
    }

    if (state.trim() === "") {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "state parameter must not be empty",
        status_code: 400,
      });
    }

    if (state.length > CONSTANTS.STATE_MAX_LENGTH) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `state parameter exceeds maximum allowed length (${CONSTANTS.STATE_MAX_LENGTH} chars)`,
        status_code: 400,
      });
    }
  }

  private validateResponseMode(responseMode: string | undefined, responseType: string): void {
    if (!responseMode) return;

    const normalizedResponseType = normalizeSpaceDelimitedSet(responseType);

    if (responseMode === "none") {
      if (normalizedResponseType !== "none") {
        throw new OIDCError({
          error: "invalid_request",
          error_description: "response_mode=none can only be used with response_type=none",
          status_code: 400,
        });
      }
      return;
    }

    if (!this.providerService.responseModesSupported?.includes(responseMode as ResponseModesSupported)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `response_mode '${responseMode}' is not supported`,
        status_code: 400,
      });
    }
  }

  private validateNonce(nonce: string | undefined, responseType: string): void {
    const normalizedResponseType = normalizeSpaceDelimitedSet(responseType);
    const requiresNonce = normalizedResponseType.includes("id_token");

    if (requiresNonce && !nonce) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "missing required 'nonce' parameter for response_type including id_token",
        status_code: 400,
      });
    }

    if (nonce && nonce.length > CONSTANTS.NONCE_MAX_LENGTH) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "'nonce' value is too long",
        status_code: 400,
      });
    }
  }

  private validatePrompt(prompt: string | undefined): void {
    if (!prompt) return;

    const prompts = prompt.split(" ");

    this.checkInvalidPromptValues(prompts);
    this.checkForDuplicates(prompts, "prompt");
    this.checkPromptNoneConstraint(prompts);
  }

  private checkInvalidPromptValues(prompts: string[]): void {
    const invalid = prompts.filter(
      (p) => !CONSTANTS.VALID_PROMPTS.includes(p as (typeof CONSTANTS.VALID_PROMPTS)[number]),
    );

    if (invalid.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Invalid prompt value(s): [${invalid.join(", ")}]. Allowed: ${CONSTANTS.VALID_PROMPTS.join(", ")}`,
        status_code: 400,
      });
    }
  }

  private checkPromptNoneConstraint(prompts: string[]): void {
    if (prompts.includes("none") && prompts.length > 1) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "prompt=none must not be used with other prompt values",
        status_code: 400,
      });
    }
  }

  private validatePKCE(codeChallenge: string | undefined, codeChallengeMethod: string | undefined): void {
    if (!codeChallenge) return;

    this.checkCodeChallengeFormat(codeChallenge);
    this.checkCodeChallengeMethod(codeChallengeMethod);
  }

  private checkCodeChallengeFormat(codeChallenge: string): void {
    if (!CONSTANTS.PKCE_REGEX.test(codeChallenge)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "invalid code_challenge format. Must be 43 to 128 chars, base64url safe.",
        status_code: 400,
      });
    }
  }

  private checkCodeChallengeMethod(codeChallengeMethod: string | undefined): void {
    const method = codeChallengeMethod as CodeChallengeMethodsSupported;
    const supportedMethods = this.providerService.codeChallengeMethodsSupported;

    if (!supportedMethods?.includes(method)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `unsupported code_challenge_method: ${method}. Supported: [${supportedMethods?.join(", ")}]`,
        status_code: 400,
      });
    }

    if (method === "plain" && !supportedMethods.includes("plain")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "code_challenge_method=plain is not allowed",
        status_code: 400,
      });
    }
  }

  // ========== Helper Methods ==========

  private checkForDuplicates(items: string[], paramName: string): void {
    const duplicates = items.filter((item, i) => items.indexOf(item) !== i);

    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Duplicate ${paramName} values not allowed: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }
  }
}
