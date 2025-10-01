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
} from "@/shared/types/oidc";
import {
  containsURIFragment,
  containsURIPath,
  containsURISearch,
  getURIProtocol,
  isHTTPS,
  isLocalhostURI,
  isURLValid,
  normalizeResponseType,
} from "../utils";
import { OIDCError } from "./oidc-error";

type ValidateConfigURIOptions = {
  enableValidityCheck: boolean;
  enableMissingCheck?: boolean;
  enableProtocolCheck?: boolean;
  enablePathCheck?: boolean;
  enableFragmentCheck?: boolean;
  enableSearchQueryCheck?: boolean;
  enableSameSiteCheck?: boolean;
};

export class ProviderService {
  constructor(private readonly config: ProviderConfig) {
    // Set defaults for scopes_supported
    if (config.scopesSupported === undefined) {
      config.scopesSupported = ["openid"];
    }

    // Set defaults for response_modes_supported
    if (config.responseModesSupported === undefined) {
      config.responseModesSupported = ["query", "fragment", "form_post"];
    }

    // Set defaults for grant_types_supported
    if (config.grantTypesSupported === undefined) {
      config.grantTypesSupported = ["authorization_code", "implicit"];
    }

    // Set defaults for token_endpoint_auth_methods_supported
    if (config.tokenEndpointAuthMethodsSupported === undefined) {
      config.tokenEndpointAuthMethodsSupported = ["client_secret_basic"];
    }

    // Set defaults for claims_supported
    if (config.claimsSupported === undefined) {
      config.claimsSupported = ["sub"];
    }

    // Set defaults for code_challenge_methods_supported
    if (config.codeChallengeMethodsSupported === undefined) {
      config.codeChallengeMethodsSupported = ["plain"];
    }

    this.validateConfig();
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

  private validateConfigURI(
    uri: string | undefined = "",
    uriType:
      | "issuer"
      | "authorization_endpoint"
      | "jwks_uri"
      | "token_endpoint"
      | "userinfo_endpoint"
      | "registration_endpoint",
    options: ValidateConfigURIOptions,
  ) {
    const protocol = getURIProtocol(uri);
    const isValid = isURLValid(uri);
    const isLocalhost = isLocalhostURI(uri);
    const isSecured = isHTTPS(uri);
    const { withPath, path } = containsURIPath(uri);
    const { withHash, fragment } = containsURIFragment(uri);
    const { withSearch, search } = containsURISearch(uri);

    if (options.enableValidityCheck) {
      if (!isValid) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} must be a valid absolute URI`,
          status_code: 400,
        });
      }
    }

    if (options.enableMissingCheck) {
      if (!uri) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Missing required field: ${uriType}`,
          status_code: 400,
        });
      }
    }

    if (options.enableProtocolCheck) {
      if (!isSecured && !(isLocalhost && protocol === "http:")) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} must use https, except for localhost/loopback`,
          status_code: 400,
        });
      }
    }

    if (options.enablePathCheck) {
      if (withPath) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} should not include a path. Use root URL as issuer. Got ${path}`,
          status_code: 400,
        });
      }
    }

    if (options.enableFragmentCheck) {
      if (withHash) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} must not contain a fragment component. Got ${fragment}`,
          status_code: 400,
        });
      }
    }

    if (options.enableSearchQueryCheck) {
      if (withSearch) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} must not contain a search query component. Got ${search}`,
          status_code: 400,
        });
      }
    }

    if (options.enableSameSiteCheck) {
      if (!uri.startsWith(this.config.issuer)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${uriType} must be under the issuer URL`,
          status_code: 400,
        });
      }
    }
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
      claims_supported: this.config.claimsSupported,
      code_challenge_methods_supported: this.config.codeChallengeMethodsSupported,
    };
  }

  private validateIssuer(issuer: string) {
    this.validateConfigURI(issuer, "issuer", {
      enableValidityCheck: true,
      enableMissingCheck: true,
      enableProtocolCheck: true,
      enablePathCheck: true,
      enableFragmentCheck: true,
      enableSearchQueryCheck: true,
    });
  }

  private validateAuthorizationEndpoint(authorizationEndpoint: string) {
    this.validateConfigURI(authorizationEndpoint, "authorization_endpoint", {
      enableValidityCheck: true,
      enableMissingCheck: true,
      enableProtocolCheck: true,
      enableFragmentCheck: true,
      enableSearchQueryCheck: true,
      enableSameSiteCheck: true,
    });
  }

  private validateJWKS(jwksURI: string) {
    this.validateConfigURI(jwksURI, "jwks_uri", {
      enableValidityCheck: true,
      enableMissingCheck: true,
      enableProtocolCheck: true,
      enableFragmentCheck: true,
      enableSearchQueryCheck: true,
      enableSameSiteCheck: true,
    });
  }

  private validateTokenEndpoint(tokenEndpoint: string) {
    this.validateConfigURI(tokenEndpoint, "token_endpoint", {
      enableValidityCheck: true,
      enableMissingCheck: true,
      enableProtocolCheck: true,
      enableFragmentCheck: true,
      enableSearchQueryCheck: true,
      enableSameSiteCheck: true,
    });
  }

  private validateUserinfo(userInfoEndpoint: string | undefined) {
    this.validateConfigURI(userInfoEndpoint, "userinfo_endpoint", {
      enableValidityCheck: !!userInfoEndpoint,
      enableProtocolCheck: !!userInfoEndpoint,
      enableFragmentCheck: !!userInfoEndpoint,
      enableSearchQueryCheck: !!userInfoEndpoint,
      enableSameSiteCheck: !!userInfoEndpoint,
      enableMissingCheck: this.config.scopesSupported?.includes("openid"),
    });
  }

  private validateRegistrationEndpoint(registrationEndpoint: string | undefined) {
    this.validateConfigURI(registrationEndpoint, "registration_endpoint", {
      enableValidityCheck: !!registrationEndpoint,
      enableProtocolCheck: !!registrationEndpoint,
      enableSameSiteCheck: !!registrationEndpoint,
      enableFragmentCheck: !!registrationEndpoint,
      enableSearchQueryCheck: !!registrationEndpoint,
    });
  }

  private validateSupportedScopes(scopes: unknown) {
    if (!Array.isArray(scopes)) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: "scopes_supported must be an array of strings",
        status_code: 400,
      });
    }

    if (!scopes.every((s) => typeof s === "string" && s.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: "scopes_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    if (!scopes.includes("openid")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: "scopes_supported should include 'openid'",
        status_code: 400,
      });
    }

    // Check for duplicates
    const duplicates = scopes.filter((item, index) => scopes.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `scopes_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private validateResponseTypesSupported(responseTypes: unknown) {
    if (!Array.isArray(responseTypes) || responseTypes.length === 0) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: "response_types_supported must not be empty",
        status_code: 400,
      });
    }

    if (!responseTypes.every((r) => typeof r === "string" && r.trim() !== "")) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: "response_types_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    const normalized = responseTypes.map((rt) => normalizeResponseType(rt));

    // Check for duplicates after normalization
    const duplicates = normalized.filter((item, index) => normalized.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: `response_types_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }

    for (const rt of normalized) {
      if (!(RESPONSE_TYPES as readonly string[]).includes(rt)) {
        throw new OIDCError({
          error: "unsupported_response_type",
          error_description: `Invalid response_type value: ${rt}`,
          status_code: 400,
        });
      }
    }
  }

  private validateSubjectTypesSupported(subjectTypes: unknown) {
    if (!Array.isArray(subjectTypes) || subjectTypes.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "subject_types_supported must not be empty",
        status_code: 400,
      });
    }

    if (!subjectTypes.every((s) => typeof s === "string" && s.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "subject_types_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    // Must include "public"
    if (!subjectTypes.includes("public")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "subject_types_supported must include 'public'",
        status_code: 400,
      });
    }

    for (const s of subjectTypes) {
      if (!SUBJECT_TYPES.includes(s as "public" | "pairwise")) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Invalid subject_type: ${s}. Allowed values: ${SUBJECT_TYPES.join(", ")}`,
          status_code: 400,
        });
      }
    }

    // Duplicates check
    const duplicates = subjectTypes.filter((item, index) => subjectTypes.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `subject_types_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private validateIdTokenSigningAlgValuesSupported(algs: unknown) {
    if (!Array.isArray(algs) || algs.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "id_token_signing_alg_values_supported must not be empty",
        status_code: 400,
      });
    }

    if (!algs.every((a) => typeof a === "string" && a.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "id_token_signing_alg_values_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    if (!algs.includes("RS256")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "id_token_signing_alg_values_supported must include 'RS256'",
        status_code: 400,
      });
    }

    for (const alg of algs) {
      if (!ID_TOKEN_SIGNING_ALGS.includes(alg)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Invalid id_token signing algorithm: ${alg}`,
          status_code: 400,
        });
      }
    }

    // Duplicates check
    const duplicates = algs.filter((item, index) => algs.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `id_token_signing_alg_values_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  public validateResponseModesSupported(modes: unknown) {
    if (!Array.isArray(modes) || modes.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "response_modes_supported must not be empty if present",
        status_code: 400,
      });
    }

    if (!modes.every((m) => typeof m === "string" && m.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "response_modes_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    for (const m of modes) {
      if (!RESPONSE_MODES.includes(m)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Non-standard response_mode detected: ${m}`,
          status_code: 400,
        });
      }
    }

    // Duplicates check
    const duplicates = modes.filter((item, index) => modes.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `response_modes_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private validateGranTypesSupported(grantTypes: unknown) {
    if (!Array.isArray(grantTypes) || grantTypes.length === 0) {
      throw new OIDCError({
        error: "unsupported_grant_type",
        error_description: "grant_types_supported must not be empty if present",
        status_code: 400,
      });
    }

    if (!grantTypes.every((g) => typeof g === "string" && g.trim() !== "")) {
      throw new OIDCError({
        error: "unsupported_grant_type",
        error_description: "grant_types_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    for (const g of grantTypes) {
      if (!STANDARD_GRANT_TYPES.includes(g)) {
        throw new OIDCError({
          error: "unsupported_grant_type",
          error_description: `Non-standard grant_type detected: ${g}`,
          status_code: 400,
        });
      }
    }

    // Duplicates check
    const duplicates = grantTypes.filter((item, index) => grantTypes.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `grant_types_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private validateTokenEndpointAuthMethodsSupported(methods: unknown) {
    if (!Array.isArray(methods) || methods.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "token_endpoint_auth_methods_supported must not be empty if present",
        status_code: 400,
      });
    }

    if (!methods.every((m) => typeof m === "string" && m.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "token_endpoint_auth_methods_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    for (const m of methods) {
      if (!TOKEN_AUTH_METHODS.includes(m)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Non-standard token_endpoint_auth_method detected: ${m}`,
          status_code: 400,
        });
      }
    }

    // Duplicates check
    const duplicates = methods.filter((item, index) => methods.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `token_endpoint_auth_methods_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private validateClaimsSupported(claims: unknown) {
    if (!Array.isArray(claims) || claims.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "claims_supported must not be empty if present",
        status_code: 400,
      });
    }

    if (!claims.every((c) => typeof c === "string" && c.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "claims_supported must contain only non-empty strings",
        status_code: 400,
      });
    }

    // Duplicates check
    const duplicates = claims.filter((item, index) => claims.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `claims_supported contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }

    // Must include "sub"
    if (!claims.includes("sub")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "claims_supported must include 'sub'",
        status_code: 400,
      });
    }

    for (const c of claims) {
      if (!CLAIMS_SUPPORTED.includes(c)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `Non-standard claim detected: ${c}`,
          status_code: 400,
        });
      }
    }
  }

  private validateCodeChallengeMethods(methods: unknown) {
    if (!Array.isArray(methods) || methods.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "code_challenge_methods_supported must not be empty",
        status_code: 400,
      });
    }

    if (
      !methods.every((m) => typeof m === "string" && CODE_CHALLENGE_METHODS.includes(m as "plain" | "S256"))
    ) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `code_challenge_methods_supported must only contain: ${CODE_CHALLENGE_METHODS.join(", ")}`,
        status_code: 400,
      });
    }

    // Duplicates check
    const duplicates = methods.filter((m, i) => methods.indexOf(m) !== i);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `code_challenge_methods_supported contains duplicates: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }

    // Strong recommendation for S256
    if (!methods.includes("S256")) {
      console.warn("PKCE without S256 is discouraged. Support for S256 is RECOMMENDED.");
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
