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
    config.scopesSupported ??= ["openid"];
    config.responseModesSupported ??= ["query", "fragment"];
    config.grantTypesSupported ??= ["authorization_code", "implicit"];
    config.tokenEndpointAuthMethodsSupported ??= ["client_secret_basic"];
    config.claimsSupported ??= ["sub"];
    config.codeChallengeMethodsSupported ??= ["plain"];

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

    this.ensureNoNonEmptyStrings("scopes_supported", scopes);
    this.ensureIncludes("scopes_suported", scopes, ["openid"]);
    this.ensureNoDuplicates("scopes_supported", scopes);
  }

  private validateResponseTypesSupported(responseTypes: unknown) {
    if (!Array.isArray(responseTypes) || responseTypes.length === 0) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: "response_types_supported must not be empty",
        status_code: 400,
      });
    }

    const normalized = responseTypes.map((rt) => normalizeResponseType(rt));
    this.ensureNoNonEmptyStrings("response_types_supported", normalized);
    this.ensureNoDuplicates("response_types_supported", normalized);
    this.ensureAllowedValuesOnly("response_types_supported", normalized, [...RESPONSE_TYPES]);
  }

  private validateSubjectTypesSupported(subjectTypes: unknown) {
    if (!Array.isArray(subjectTypes) || subjectTypes.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "subject_types_supported must not be empty",
        status_code: 400,
      });
    }

    this.ensureNoNonEmptyStrings("subject_types_supported", subjectTypes);
    this.ensureIncludes("subject_types_supported", subjectTypes, ["public"]);
    this.ensureAllowedValuesOnly("subject_types_supported", subjectTypes, [...SUBJECT_TYPES]);
    this.ensureNoDuplicates("subject_types_supported", subjectTypes);
  }

  private validateIdTokenSigningAlgValuesSupported(algs: unknown) {
    if (!Array.isArray(algs) || algs.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "id_token_signing_alg_values_supported must not be empty",
        status_code: 400,
      });
    }

    this.ensureNoNonEmptyStrings("id_token_signing_values_supported", algs);
    this.ensureIncludes("id_token_signing_values_supported", algs, ["RS256"]);
    this.ensureAllowedValuesOnly("id_token_signing_values_supported", algs, [...ID_TOKEN_SIGNING_ALGS]);
    this.ensureNoDuplicates("id_token_signing_alg_values_supported", algs);
  }

  public validateResponseModesSupported(modes: unknown) {
    if (!Array.isArray(modes) || modes.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "response_modes_supported must not be empty if present",
        status_code: 400,
      });
    }

    this.ensureNoNonEmptyStrings("response_modes_supported", modes);
    this.ensureAllowedValuesOnly("response_modes_supported", modes, [...RESPONSE_MODES]);
    this.ensureNoDuplicates("response_modes_supported", modes);
  }

  private validateGranTypesSupported(grantTypes: unknown) {
    if (!Array.isArray(grantTypes) || grantTypes.length === 0) {
      throw new OIDCError({
        error: "unsupported_grant_type",
        error_description: "grant_types_supported must not be empty if present",
        status_code: 400,
      });
    }

    this.ensureNoNonEmptyStrings("grant_types_supported", grantTypes);
    this.ensureAllowedValuesOnly("grant_types_supported", grantTypes, [...STANDARD_GRANT_TYPES]);
    this.ensureNoDuplicates("grant_types_supported", grantTypes);
  }

  private validateTokenEndpointAuthMethodsSupported(methods: unknown) {
    if (!Array.isArray(methods) || methods.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "token_endpoint_auth_methods_supported must not be empty if present",
        status_code: 400,
      });
    }

    this.ensureNoNonEmptyStrings("token_endpoint_auth_methods_supported", methods);
    this.ensureAllowedValuesOnly("token_endpoint_auth_methods_supported", methods, [...TOKEN_AUTH_METHODS]);
    this.ensureNoDuplicates("token_endpoint_auth_methods_supported", methods);
  }

  private validateClaimsSupported(claims: unknown) {
    if (!Array.isArray(claims) || claims.length === 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "claims_supported must not be empty if present",
        status_code: 400,
      });
    }

    this.ensureIncludes("claims_supported", claims, ["sub"]);
    this.ensureNoNonEmptyStrings("claims_supported", claims);
    this.ensureAllowedValuesOnly("claims_supported", claims, [...CLAIMS_SUPPORTED]);
    this.ensureNoDuplicates("claims_supported", claims);
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

    // Strong recommendation for S256
    if (!methods.includes("S256")) {
      console.warn("PKCE without S256 is discouraged. Support for S256 is RECOMMENDED.");
    }

    this.ensureNoDuplicates("code_challenge_methods_supported", methods);
  }

  private ensureNoDuplicates(name: string, arr: string[]) {
    const duplicates = arr.filter((item, index) => arr.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} contains duplicate values: ${[...new Set(duplicates)].join(", ")}`,
        status_code: 400,
      });
    }
  }

  private ensureNoNonEmptyStrings(name: string, arr: string[]) {
    if (!arr.every((s) => typeof s === "string" && s.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `${name} must contain only non-empty strings`,
        status_code: 400,
      });
    }
  }

  private ensureIncludes(name: string, arr: string[], required: string[]) {
    for (const req of required) {
      if (!arr.includes(req)) {
        throw new OIDCError({
          error: "invalid_request",
          error_description: `${name} must include "${req}"`,
          status_code: 400,
        });
      }
    }
  }

  public ensureAllowedValuesOnly(name: string, arr: string[], ref: string[]) {
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
