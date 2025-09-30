import { CamelCasedProperties } from "./common";

export type ResponseTypesSupported =
  | "code"
  | "id_token"
  | "token id_token"
  | "code id_token"
  | "code token"
  | "code id_token token";

export type GrantTypesSupported = "authorization_code" | "implicit" | "refresh_token" | "client_credentials";
export type TokenEndpointAuthMethodSupported = "client_secret_basic" | "client_secret_post" | "none";
export type SubjectTypesSupported = "public" | "pairwise";
export type IdTokenSigningAlgValuesSupported = "RS256" | "HS256" | "ES256";
export type ScopesSupported = "openid" | "profile" | "email" | "address" | "phone" | "offline_access";
export type ResponseModesSupported = "query" | "fragment" | "form_post";
export type ClaimsSupported = "sub" | "name" | "email" | "preferred_username" | "given_name" | "family_name";
export type CodeChallengeMethodsSupported = "S256" | "plain";

export type DiscoveryDocument = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  scopes_supported?: ScopesSupported[];
  response_types_supported: ResponseTypesSupported[];
  subject_types_supported: SubjectTypesSupported[];
  id_token_signing_alg_values_supported: IdTokenSigningAlgValuesSupported[];
  response_modes_supported?: ResponseModesSupported[];
  grant_types_supported?: GrantTypesSupported[];
  token_endpoint_auth_methods_supported: TokenEndpointAuthMethodSupported[];
  claims_supported?: ClaimsSupported[];
  code_challenge_methods_supported?: CodeChallengeMethodsSupported[];
};

export type OIDCProvider = CamelCasedProperties<DiscoveryDocument> & {
  requirePCKCE?: boolean;
};
