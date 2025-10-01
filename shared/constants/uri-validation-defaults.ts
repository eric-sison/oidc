import { DiscoveryDocument, ValidateConfigURIOptions } from "../types/oidc";

// sensible defaults for each type
export const URI_VALIDATION_DEFAULTS: Record<
  keyof Pick<
    DiscoveryDocument,
    | "issuer"
    | "authorization_endpoint"
    | "jwks_uri"
    | "token_endpoint"
    | "userinfo_endpoint"
    | "registration_endpoint"
  >,
  ValidateConfigURIOptions
> = {
  issuer: {
    valid: true,
    required: true,
    httpsOnly: true,
    noPath: true,
    noFragment: true,
    noQuery: true,
    sameOrigin: false,
  },
  authorization_endpoint: {
    valid: true,
    required: true,
    httpsOnly: true,
    noFragment: true,
    noQuery: true,
    sameOrigin: true,
    noPath: false,
  },
  jwks_uri: {
    valid: true,
    required: true,
    httpsOnly: true,
    noFragment: true,
    noQuery: true,
    sameOrigin: true,
    noPath: false,
  },
  token_endpoint: {
    valid: true,
    required: true,
    httpsOnly: true,
    noFragment: true,
    noQuery: true,
    sameOrigin: true,
    noPath: false,
  },
  userinfo_endpoint: {
    valid: false, // becomes true if uri is present
    required: false, // becomes true if "openid" scope
    httpsOnly: false, // becomes true if uri is present
    noFragment: false,
    noQuery: false,
    sameOrigin: false,
    noPath: false,
  },
  registration_endpoint: {
    valid: false, // only if present
    required: false,
    httpsOnly: false,
    noFragment: false,
    noQuery: false,
    sameOrigin: false,
    noPath: false,
  },
};
