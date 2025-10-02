/* eslint-disable  @typescript-eslint/no-explicit-any */

import {
  DiscoveryDocument,
  ValidateConfigURIOptions,
  ID_TOKEN_SIGNING_ALGS,
  RESPONSE_TYPES,
  SUBJECT_TYPES,
  RESPONSE_MODES,
  STANDARD_GRANT_TYPES,
  TOKEN_AUTH_METHODS,
  CLAIMS_SUPPORTED,
  CODE_CHALLENGE_METHODS,
  OIDCErrorCode,
  ScopesSupported,
  ResponseModesSupported,
  GrantTypesSupported,
  TokenEndpointAuthMethodsSupported,
  ClaimsSupported,
  CodeChallengeMethodsSupported,
} from "@/shared/types/oidc";

/**
 * URI validation configuration for each endpoint
 */
export const URI_VALIDATION_RULES: Record<
  string,
  {
    configKey: keyof Pick<
      DiscoveryDocument,
      | "issuer"
      | "authorization_endpoint"
      | "jwks_uri"
      | "token_endpoint"
      | "userinfo_endpoint"
      | "registration_endpoint"
    >;
    rules: Partial<ValidateConfigURIOptions>;
  }
> = {
  issuer: {
    configKey: "issuer",
    rules: {
      valid: true,
      required: true,
      httpsOnly: true,
      noPath: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: false,
    },
  },
  authorizationEndpoint: {
    configKey: "authorization_endpoint",
    rules: {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    },
  },
  jwksUri: {
    configKey: "jwks_uri",
    rules: {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    },
  },
  tokenEndpoint: {
    configKey: "token_endpoint",
    rules: {
      valid: true,
      required: true,
      httpsOnly: true,
      noFragment: true,
      noQuery: true,
      sameOrigin: true,
      noPath: false,
    },
  },
  registrationEndpoint: {
    configKey: "registration_endpoint",
    rules: {
      valid: true,
      httpsOnly: true,
      sameOrigin: true,
      noFragment: true,
      noQuery: true,
      required: false, // Optional endpoint
    },
  },
};

/**
 * Array validation configuration for supported values
 */
export const ARRAY_VALIDATION_RULES: Record<
  string,
  {
    configKey: keyof DiscoveryDocument;
    rules: {
      mustNotBeEmpty?: boolean;
      required?: string[];
      allowed?: string[];
      errorCode?: OIDCErrorCode;
    };
    preProcess?: (value: any) => any;
    postValidate?: (value: any) => void;
  }
> = {
  scopesSupported: {
    configKey: "scopes_supported",
    rules: {
      mustNotBeEmpty: true,
      required: ["openid"],
      errorCode: "invalid_scope",
    },
  },
  responseTypesSupported: {
    configKey: "response_types_supported",
    rules: {
      mustNotBeEmpty: true,
      required: ["code"],
      allowed: [...RESPONSE_TYPES],
      errorCode: "unsupported_response_type",
    },
  },
  subjectTypesSupported: {
    configKey: "subject_types_supported",
    rules: {
      mustNotBeEmpty: true,
      required: ["public"],
      allowed: [...SUBJECT_TYPES],
    },
  },
  idTokenSigningAlgValuesSupported: {
    configKey: "id_token_signing_alg_values_supported",
    rules: {
      mustNotBeEmpty: true,
      required: ["RS256"],
      allowed: [...ID_TOKEN_SIGNING_ALGS],
    },
  },
  responseModesSupported: {
    configKey: "response_modes_supported",
    rules: {
      mustNotBeEmpty: true,
      allowed: [...RESPONSE_MODES],
    },
  },
  grantTypesSupported: {
    configKey: "grant_types_supported",
    rules: {
      mustNotBeEmpty: true,
      allowed: [...STANDARD_GRANT_TYPES],
      required: ["authorization_code"],
      errorCode: "unsupported_grant_type",
    },
  },
  tokenEndpointAuthMethodsSupported: {
    configKey: "token_endpoint_auth_methods_supported",
    rules: {
      mustNotBeEmpty: true,
      allowed: [...TOKEN_AUTH_METHODS],
      required: ["client_secret_basic"],
    },
  },
  claimsSupported: {
    configKey: "claims_supported",
    rules: {
      mustNotBeEmpty: true,
      required: ["sub"],
      allowed: [...CLAIMS_SUPPORTED],
    },
  },
  codeChallengeMethodsSupported: {
    configKey: "code_challenge_methods_supported",
    rules: {
      mustNotBeEmpty: true,
      allowed: [...CODE_CHALLENGE_METHODS],
    },
    postValidate: (value: string[]) => {
      // Strong recommendation for S256
      if (!value.includes("S256")) {
        console.warn("PKCE without S256 is discouraged. Support for S256 is RECOMMENDED.");
      }
    },
  },
};

/**
 * Default values for optional configuration fields
 */
export const DEFAULT_CONFIG_VALUES = {
  scopesSupported: ["openid"] as ScopesSupported[],
  responseModesSupported: ["query", "fragment"] as ResponseModesSupported[],
  grantTypesSupported: ["authorization_code"] as GrantTypesSupported[],
  tokenEndpointAuthMethodsSupported: ["client_secret_basic"] as TokenEndpointAuthMethodsSupported[],
  claimsSupported: ["sub"] as ClaimsSupported[],
  codeChallengeMethodsSupported: ["S256"] as CodeChallengeMethodsSupported[],
} as const;
