import { ProviderConfig } from "@/shared/types/oidc";
import { DEFAULT_CONFIG_VALUES } from "./validation-config";

/**
 * Builder for creating ProviderConfig instances with sensible defaults
 *
 * @example
 * ```typescript
 * const config = new ProviderConfigBuilder()
 *   .withIssuer("https://example.com")
 *   .withAuthorizationEndpoint("https://example.com/authorize")
 *   .withTokenEndpoint("https://example.com/token")
 *   .withJwksUri("https://example.com/jwks")
 *   .withSubjectTypesSupported(["public", "pairwise"])
 *   .build();
 * ```
 */
export class ProviderConfigBuilder {
  private config: Partial<ProviderConfig> = {};

  /**
   * Set the issuer URL (required)
   */
  withIssuer(issuer: string): this {
    this.config.issuer = issuer;
    return this;
  }

  /**
   * Set the authorization endpoint URL (required)
   */
  withAuthorizationEndpoint(authorizationEndpoint: string): this {
    this.config.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  /**
   * Set the token endpoint URL (required)
   */
  withTokenEndpoint(tokenEndpoint: string): this {
    this.config.tokenEndpoint = tokenEndpoint;
    return this;
  }

  /**
   * Set the JWKS URI (required)
   */
  withJwksUri(jwksUri: string): this {
    this.config.jwksUri = jwksUri;
    return this;
  }

  /**
   * Set the userinfo endpoint URL (optional)
   */
  withUserinfoEndpoint(userinfoEndpoint: string): this {
    this.config.userinfoEndpoint = userinfoEndpoint;
    return this;
  }

  /**
   * Set the registration endpoint URL (optional)
   */
  withRegistrationEndpoint(registrationEndpoint: string): this {
    this.config.registrationEndpoint = registrationEndpoint;
    return this;
  }

  /**
   * Set supported scopes
   * @default ["openid"]
   */
  withScopesSupported(scopes: string[]): this {
    this.config.scopesSupported = scopes;
    return this;
  }

  /**
   * Add additional scopes to the default or existing list
   */
  addScopes(...scopes: string[]): this {
    const existing = this.config.scopesSupported || DEFAULT_CONFIG_VALUES.scopesSupported;
    this.config.scopesSupported = [...new Set([...existing, ...scopes])];
    return this;
  }

  /**
   * Set supported response types (required)
   */
  withResponseTypesSupported(responseTypes: string[]): this {
    this.config.responseTypesSupported = responseTypes;
    return this;
  }

  /**
   * Set supported subject types (required)
   */
  withSubjectTypesSupported(subjectTypes: string[]): this {
    this.config.subjectTypesSupported = subjectTypes;
    return this;
  }

  /**
   * Set supported ID token signing algorithms (required)
   */
  withIdTokenSigningAlgValuesSupported(algs: string[]): this {
    this.config.idTokenSigningAlgValuesSupported = algs;
    return this;
  }

  /**
   * Set supported response modes
   * @default ["query", "fragment"]
   */
  withResponseModesSupported(modes: string[]): this {
    this.config.responseModesSupported = modes;
    return this;
  }

  /**
   * Set supported grant types
   * @default ["authorization_code"]
   */
  withGrantTypesSupported(grantTypes: string[]): this {
    this.config.grantTypesSupported = grantTypes;
    return this;
  }

  /**
   * Add additional grant types to the default or existing list
   */
  addGrantTypes(...grantTypes: string[]): this {
    const existing = this.config.grantTypesSupported || DEFAULT_CONFIG_VALUES.grantTypesSupported;
    this.config.grantTypesSupported = [...new Set([...existing, ...grantTypes])];
    return this;
  }

  /**
   * Set supported token endpoint authentication methods
   * @default ["client_secret_basic"]
   */
  withTokenEndpointAuthMethodsSupported(methods: string[]): this {
    this.config.tokenEndpointAuthMethodsSupported = methods;
    return this;
  }

  /**
   * Set supported claims
   * @default ["sub"]
   */
  withClaimsSupported(claims: string[]): this {
    this.config.claimsSupported = claims;
    return this;
  }

  /**
   * Add additional claims to the default or existing list
   */
  addClaims(...claims: string[]): this {
    const existing = this.config.claimsSupported || DEFAULT_CONFIG_VALUES.claimsSupported;
    this.config.claimsSupported = [...new Set([...existing, ...claims])];
    return this;
  }

  /**
   * Set supported code challenge methods
   * @default ["S256"]
   */
  withCodeChallengeMethodsSupported(methods: string[]): this {
    this.config.codeChallengeMethodsSupported = methods;
    return this;
  }

  /**
   * Create a builder from an existing config (useful for modifications)
   */
  static fromConfig(config: ProviderConfig): ProviderConfigBuilder {
    const builder = new ProviderConfigBuilder();
    builder.config = { ...config };
    return builder;
  }

  /**
   * Build the final ProviderConfig with defaults applied
   * @throws Error if required fields are missing
   */
  build(): ProviderConfig {
    // Validate required fields
    this.validateRequiredFields();

    // Apply defaults for optional fields
    const configWithDefaults: ProviderConfig = {
      issuer: this.config.issuer!,
      authorizationEndpoint: this.config.authorizationEndpoint!,
      tokenEndpoint: this.config.tokenEndpoint!,
      jwksUri: this.config.jwksUri!,
      responseTypesSupported: this.config.responseTypesSupported!,
      subjectTypesSupported: this.config.subjectTypesSupported!,
      idTokenSigningAlgValuesSupported: this.config.idTokenSigningAlgValuesSupported!,

      // Optional fields with defaults
      scopesSupported: this.config.scopesSupported ?? DEFAULT_CONFIG_VALUES.scopesSupported,
      responseModesSupported:
        this.config.responseModesSupported ?? DEFAULT_CONFIG_VALUES.responseModesSupported,
      grantTypesSupported: this.config.grantTypesSupported ?? DEFAULT_CONFIG_VALUES.grantTypesSupported,
      tokenEndpointAuthMethodsSupported:
        this.config.tokenEndpointAuthMethodsSupported ??
        DEFAULT_CONFIG_VALUES.tokenEndpointAuthMethodsSupported,
      claimsSupported: this.config.claimsSupported ?? DEFAULT_CONFIG_VALUES.claimsSupported,
      codeChallengeMethodsSupported:
        this.config.codeChallengeMethodsSupported ?? DEFAULT_CONFIG_VALUES.codeChallengeMethodsSupported,

      // Truly optional fields
      userinfoEndpoint: this.config.userinfoEndpoint,
      registrationEndpoint: this.config.registrationEndpoint,
    };

    return configWithDefaults;
  }

  /**
   * Validate that all required fields are present
   */
  private validateRequiredFields(): void {
    const requiredFields: (keyof ProviderConfig)[] = [
      "issuer",
      "authorizationEndpoint",
      "tokenEndpoint",
      "jwksUri",
      "responseTypesSupported",
      "subjectTypesSupported",
      "idTokenSigningAlgValuesSupported",
    ];

    const missingFields = requiredFields.filter((field) => !this.config[field]);

    if (missingFields.length > 0) {
      throw new Error(`ProviderConfigBuilder: Missing required fields: ${missingFields.join(", ")}`);
    }
  }

  /**
   * Reset the builder to start fresh
   */
  reset(): this {
    this.config = {};
    return this;
  }
}
