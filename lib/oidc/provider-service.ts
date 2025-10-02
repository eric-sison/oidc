import { DiscoveryDocument, ProviderConfig } from "@/shared/types/oidc";
import { URIValidator } from "./uri-validator";
import { ArrayValidator } from "./array-validator";
import { URI_VALIDATION_RULES, ARRAY_VALIDATION_RULES } from "./validation-config";
import { normalizeSpaceDelimitedSet } from "@/lib/utils";

export class ProviderService {
  private readonly uriValidator: URIValidator;
  private readonly arrayValidator: ArrayValidator;

  constructor(private readonly config: ProviderConfig) {
    this.uriValidator = new URIValidator(config.issuer);
    this.arrayValidator = new ArrayValidator();
  }

  /**
   * Validate the entire provider configuration
   */
  public validateConfig(): void {
    this.validateAllURIs();
    this.validateUserinfoEndpoint();
    this.validateAllArrays();
  }

  /**
   * Validate all URI endpoints using configuration-driven approach
   */
  private validateAllURIs(): void {
    Object.entries(URI_VALIDATION_RULES).forEach(([key, { configKey, rules }]) => {
      const value = this.getConfigValue(key);

      // Skip validation for optional endpoints that are not provided
      if (!rules.required && !value) {
        return;
      }

      this.uriValidator.validateURI(value as string, configKey, rules);
    });
  }

  /**
   * Special validation for userinfo endpoint (depends on scopes)
   */
  private validateUserinfoEndpoint(): void {
    const userInfoEndpoint = this.config.userinfoEndpoint;
    const hasOpenIdScope = this.config.scopesSupported?.includes("openid");

    this.uriValidator.validateURI(userInfoEndpoint, "userinfo_endpoint", {
      valid: !!userInfoEndpoint,
      httpsOnly: !!userInfoEndpoint,
      noFragment: !!userInfoEndpoint,
      noQuery: !!userInfoEndpoint,
      sameOrigin: !!userInfoEndpoint,
      required: hasOpenIdScope,
    });
  }

  /**
   * Validate all array fields using configuration-driven approach
   */
  private validateAllArrays(): void {
    Object.entries(ARRAY_VALIDATION_RULES).forEach(
      ([key, { configKey, rules, preProcess, postValidate }]) => {
        let value = this.getConfigValue(key);

        // Apply preprocessing if defined (e.g., normalize response types)
        if (preProcess) {
          value = preProcess(value);
        }

        // Special handling for responseTypesSupported normalization
        if (key === "responseTypesSupported" && Array.isArray(value)) {
          value = value.map((rt: string) => normalizeSpaceDelimitedSet(rt));
        }

        this.arrayValidator.validateStringArray(configKey, value, rules);

        // Apply post-validation logic if defined (e.g., S256 warning)
        if (postValidate && value) {
          postValidate(value);
        }
      },
    );
  }

  /**
   * Helper to get config value by key (handles camelCase to config mapping)
   */
  private getConfigValue(key: string): any {
    return (this.config as any)[key];
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

  // Getters
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
