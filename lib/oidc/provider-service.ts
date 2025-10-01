import { DiscoveryDocument, ProviderConfig, TokenEndpointAuthMethodsSupported } from "@/shared/types/oidc";
import {
  containsURIFragment,
  containsURIPath,
  containsURISearch,
  getURIProtocol,
  isHTTPS,
  isLocalhostURI,
  isURLValid,
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
    if (config.scopesSupported === undefined) {
      config.scopesSupported = ["openid"];
    }

    if (config.responseModesSupported === undefined) {
      config.responseModesSupported = ["query", "fragment"];
    }

    if (config.grantTypesSupported === undefined) {
      config.grantTypesSupported = ["authorization_code"];
    }

    if (config.claimsSupported === undefined) {
      config.claimsSupported = ["sub"];
    }

    if (config.codeChallengeMethodsSupported === undefined) {
      config.codeChallengeMethodsSupported = ["S256"];
    }

    if (config.requirePKCEForPublicClients === undefined) {
      config.requirePKCEForPublicClients = true;
    }

    if (config.requireState === undefined) {
      config.requireState = true;
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
    console.log(registrationEndpoint);
    this.validateConfigURI(registrationEndpoint, "registration_endpoint", {
      enableValidityCheck: !!registrationEndpoint,
      enableProtocolCheck: !!registrationEndpoint,
      enableSameSiteCheck: !!registrationEndpoint,
      enableFragmentCheck: !!registrationEndpoint,
      enableSearchQueryCheck: !!registrationEndpoint,
    });
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
