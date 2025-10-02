import { OIDCError } from "./oidc-error";
import {
  DiscoveryDocument,
  ProviderConfig,
  ID_TOKEN_SIGNING_ALGS,
  RESPONSE_TYPES,
  SUBJECT_TYPES,
  RESPONSE_MODES,
  STANDARD_GRANT_TYPES,
  TOKEN_AUTH_METHODS,
  CLAIMS_SUPPORTED,
  CODE_CHALLENGE_METHODS,
  OIDCErrorCode,
  ValidateConfigURIOptions,
} from "@/shared/types/oidc";
import {
  containsURIFragment,
  containsURIPath,
  containsURISearch,
  getURIProtocol,
  isHTTPS,
  isLocalhostURI,
  isURLValid,
  normalizeSpaceDelimitedSet,
} from "../utils";

export class ProviderService {
  constructor(private readonly config: ProviderConfig) {
    config.scopesSupported ??= ["openid"];
    config.responseModesSupported ??= ["query", "fragment"];
    config.grantTypesSupported ??= ["authorization_code"];
    config.tokenEndpointAuthMethodsSupported ??= ["client_secret_basic"];
    config.claimsSupported ??= ["sub"];
    config.codeChallengeMethodsSupported ??= ["S256"];
  }

  public validateConfig() {
    this.validateIssuer(this.config.issuer);
    this.validateAuthorizationEndpoint(this.config.authorizationEndpoint);
    this.validateJWKS(this.config.jwksUri);
    this.validateTokenEndpoint(this.config.tokenEndpoint);
    this.validateUserinfo(this.config.userinfoEndpoint);
    this.validateRegistrationEndpoint(this.config.registrationEndpoint);
    this.validateSupportedScopes(this.config.scopesSupported);
    this.validateResponseTypesSupported(this.config.responseTypesSupported);
    this.validateSubjectTypesSupported(this.config.subjectTypesSupported);
    this.validateIdTokenSigningAlgValuesSupported(this.config.idTokenSigningAlgValuesSupported);
    this.validateResponseModesSupported(this.config.responseModesSupported);
    this.validateGranTypesSupported(this.config.grantTypesSupported);
    this.validateTokenEndpointAuthMethodsSupported(this.config.tokenEndpointAuthMethodsSupported);
    this.validateClaimsSupported(this.config.claimsSupported);
    this.validateCodeChallengeMethods(this.config.codeChallengeMethodsSupported);
  }

  public getDiscoveryDocument(): DiscoveryDocument {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: this.config.authorizationEndpoint,
      jwks_uri: this.config.jwksUri,
      token_endpoint: this.config.tokenEndpoint,
      userinfo_endpoint: this.config.userinfoEndpoint,
      registration_endpoint: this.config.registrationEndpoint,
      scopes_supported: this.config.scopesSupported,
      response_types_supported: this.config.responseTypesSupported,
      subject_types_supported: this.config.subjectTypesSupported,
      id_token_signing_alg_values_supported: this.config.idTokenSigningAlgValuesSupported,
      response_modes_supported: this.config.responseModesSupported,
      grant_types_supported: this.config.grantTypesSupported,
      token_endpoint_auth_methods_supported: this.config.tokenEndpointAuthMethodsSupported,
      code_challenge_methods_supported: this.config.codeChallengeMethodsSupported,
      claims_supported: this.config.claimsSupported,
    };
  }

  private validateIssuer(issuer: string) {
    this.validateURI(issuer, "issuer", {
      valid: true,
      required: true,
      httpsOnly: true,
      noPath: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: false,
    });
  }

  private validateAuthorizationEndpoint(authorizationEndpoint: string) {
    this.validateURI(authorizationEndpoint, "authorization_endpoint", {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    });
  }

  private validateJWKS(jwksURI: string) {
    this.validateURI(jwksURI, "jwks_uri", {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    });
  }

  private validateTokenEndpoint(tokenEndpoint: string) {
    this.validateURI(tokenEndpoint, "token_endpoint", {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    });
  }

  private validateUserinfo(userInfoEndpoint: string | undefined) {
    this.validateURI(userInfoEndpoint, "userinfo_endpoint", {
      valid: !!userInfoEndpoint,
      httpsOnly: !!userInfoEndpoint,
      noFragment: !!userInfoEndpoint,
      noQuery: !!userInfoEndpoint,
      sameOrigin: !!userInfoEndpoint,
      required: this.config.scopesSupported?.includes("openid"),
    });
  }

  private validateRegistrationEndpoint(registrationEndpoint: string | undefined) {
    if (registrationEndpoint) {
      this.validateURI(registrationEndpoint, "registration_endpoint", {
        valid: true,
        httpsOnly: true,
        sameOrigin: true,
        noFragment: true,
        noQuery: true,
      });
    }
  }

  private validateSupportedScopes(scopes: string[] | undefined) {
    this.validateStringArray("scopes_supported", scopes, {
      mustNotBeEmpty: true,
      required: ["openid"],
      errorCode: "invalid_scope",
    });
  }

  private validateResponseTypesSupported(responseTypes: string[]) {
    const normalized = responseTypes.map((rt) => normalizeSpaceDelimitedSet(rt));
    this.validateStringArray("response_types_supported", normalized, {
      mustNotBeEmpty: true,
      required: ["code"],
      allowed: [...RESPONSE_TYPES],
      errorCode: "unsupported_response_type",
    });
  }

  private validateSubjectTypesSupported(subjectTypes: string[]) {
    this.validateStringArray("subject_types_supported", subjectTypes, {
      mustNotBeEmpty: true,
      required: ["public"],
      allowed: [...SUBJECT_TYPES],
    });
  }

  private validateIdTokenSigningAlgValuesSupported(algs: string[]) {
    this.validateStringArray("id_token_signing_alg_values_supported", algs, {
      mustNotBeEmpty: true,
      required: ["RS256"],
      allowed: [...ID_TOKEN_SIGNING_ALGS],
    });
  }

  private validateResponseModesSupported(modes: string[] | undefined) {
    this.validateStringArray("response_modes_supported", modes, {
      mustNotBeEmpty: true,
      allowed: [...RESPONSE_MODES],
    });
  }

  private validateGranTypesSupported(grantTypes: string[] | undefined) {
    this.validateStringArray("grant_types_supported", grantTypes, {
      mustNotBeEmpty: true,
      allowed: [...STANDARD_GRANT_TYPES],
      required: ["authorization_code"],
      errorCode: "unsupported_grant_type",
    });
  }

  private validateTokenEndpointAuthMethodsSupported(authMethods: string[] | undefined) {
    this.validateStringArray("token_endpoint_auth_methods_supported", authMethods, {
      mustNotBeEmpty: true,
      allowed: [...TOKEN_AUTH_METHODS],
      required: ["client_secret_basic"],
    });
  }

  private validateClaimsSupported(claims: unknown) {
    this.validateStringArray("claims_supported", claims, {
      mustNotBeEmpty: true,
      required: ["sub"],
      allowed: [...CLAIMS_SUPPORTED],
    });
  }

  private validateCodeChallengeMethods(methods: unknown) {
    this.validateStringArray("code_challenge_methods_supported", methods, {
      mustNotBeEmpty: true,
      allowed: [...CODE_CHALLENGE_METHODS],
    });

    const arr = methods as string[];

    // Strong recommendation for S256
    if (!arr.includes("S256")) {
      console.warn("PKCE without S256 is discouraged. Support for S256 is RECOMMENDED.");
    }
  }

  private validateURI(
    uri: string | undefined,
    uriType: keyof Pick<
      DiscoveryDocument,
      | "issuer"
      | "authorization_endpoint"
      | "jwks_uri"
      | "token_endpoint"
      | "userinfo_endpoint"
      | "registration_endpoint"
    >,
    options: Partial<ValidateConfigURIOptions> = {},
  ) {
    const safeUri = uri ?? ""; // always a string

    const protocol = getURIProtocol(safeUri);
    const isValid = isURLValid(safeUri);
    const isLocalhost = isLocalhostURI(safeUri);
    const isSecured = isHTTPS(safeUri);
    const { withPath, path } = containsURIPath(safeUri);
    const { withHash, fragment } = containsURIFragment(safeUri);
    const { withSearch, search } = containsURISearch(safeUri);

    if (options.valid && !isValid) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} must be a valid absolute URI`,
        status_code: 400,
      });
    }

    if (options.required && !uri) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Missing required field: ${uriType}`,
        status_code: 400,
      });
    }

    if (options.httpsOnly && !(!uri || isSecured || (isLocalhost && protocol === "http:"))) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} must use https, except for localhost/loopback`,
        status_code: 400,
      });
    }

    if (options.noPath && withPath) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} should not include a path. Use root URL as issuer. Got ${path}`,
        status_code: 400,
      });
    }

    if (options.noFragment && withHash) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} must not contain a fragment component. Got ${fragment}`,
        status_code: 400,
      });
    }

    if (options.noQuery && withSearch) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} must not contain a search query component. Got ${search}`,
        status_code: 400,
      });
    }

    if (options.sameOrigin && uri && !uri.startsWith(this.config.issuer)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${uriType} must be under the issuer URL`,
        status_code: 400,
      });
    }
  }

  private validateStringArray(
    name: keyof DiscoveryDocument,
    arr: unknown,
    options: {
      required?: string[];
      allowed?: string[];
      mustNotBeEmpty?: boolean;
      errorCode?: OIDCErrorCode; // customize OIDC error
    } = {},
  ) {
    if (!Array.isArray(arr) || (options.mustNotBeEmpty && arr.length === 0)) {
      throw new OIDCError({
        error: options.errorCode ?? "invalid_request",
        error_description: `${name} must be a non-empty array of strings`,
        status_code: 400,
      });
    }

    if (!arr.every((s) => typeof s === "string" && s.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} must contain only non-empty strings`,
        status_code: 400,
      });
    }

    this.ensureNoDuplicates(name, arr);

    if (options.required) {
      this.ensureIncludes(name, arr, options.required);
    }

    if (options.allowed) {
      this.ensureAllowedValuesOnly(name, arr, options.allowed);
    }
  }

  private ensureNoDuplicates(name: string, arr: string[]) {
    const duplicates = arr.filter((item, index) => arr.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} contains duplicate values: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private ensureIncludes(name: string, arr: string[], required: string[]) {
    const missing = required.filter((req) => !arr.includes(req));

    for (const req of required) {
      if (!arr.includes(req)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${name} must include: [${missing.join(", ")}]`,
          status_code: 400,
        });
      }
    }
  }

  private ensureAllowedValuesOnly(name: string, arr: string[], ref: string[]) {
    for (const rt of arr) {
      if (!(ref as readonly string[]).includes(rt)) {
        throw new OIDCError({
          error: "unsupported_response_type",
          error_description: `Invalid ${name} value: ${rt}. Allowed values: ${ref.join(", ")}`,
          status_code: 400,
        });
      }
    }
  }

  get issuer() {
    return this.config.issuer;
  }

  get authorizationEndpoint() {
    return this.config.authorizationEndpoint;
  }

  get tokenEndpoint() {
    return this.config.tokenEndpoint;
  }

  get userinfoEndpoint() {
    return this.config.userinfoEndpoint;
  }

  get jwksURI() {
    return this.config.jwksUri;
  }

  get registrationEndpoint() {
    return this.config.registrationEndpoint;
  }

  get scopesSupported() {
    return this.config.scopesSupported;
  }

  get responseTypesSupported() {
    return this.config.responseTypesSupported;
  }

  get responseModesSupported() {
    return this.config.responseModesSupported;
  }

  get grantTypesSupported() {
    return this.config.grantTypesSupported;
  }

  get tokenEndpointAuthMethodsSupported() {
    return this.config.tokenEndpointAuthMethodsSupported;
  }

  get claimsSupported() {
    return this.config.claimsSupported;
  }

  get codeChallengeMethodsSupported() {
    return this.config.codeChallengeMethodsSupported;
  }
}
