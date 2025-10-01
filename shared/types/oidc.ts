import z from "zod";
import { CamelCasedProperties, SnakeCasedProperties } from "./common";
import { AuthorizationRequestSchema } from "../validators/authorization-request";

export type OIDCErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable"
  | "interaction_required"
  | "login_required"
  | "account_selection_required"
  | "consent_required"
  | "invalid_request_uri"
  | "invalid_request_object"
  | "request_not_supported"
  | "request_uri_not_supported"
  | "registration_not_supported";

export type OIDCErrorParams = {
  error: OIDCErrorCode;
  error_description?: string;
  error_uri?: string;
  state?: string; // per spec, returned if present in request
};

export type ResponseTypesSupported =
  | "code"
  | "id_token"
  | "token id_token"
  | "code id_token"
  | "code token"
  | "code id_token token";

export type GrantTypesSupported = "authorization_code" | "implicit" | "refresh_token" | "client_credentials";
export type TokenEndpointAuthMethodsSupported = "client_secret_basic" | "client_secret_post" | "none";
export type SubjectTypesSupported = "public" | "pairwise";
export type IdTokenSigningAlgValuesSupported = "RS256" | "HS256" | "ES256";
export type ScopesSupported = "openid" | "profile" | "email" | "address" | "phone" | "offline_access";
export type ResponseModesSupported = "query" | "fragment" | "form_post";
export type ClaimsSupported = "sub" | "name" | "email" | "preferred_username" | "given_name" | "family_name";
export type CodeChallengeMethodsSupported = "S256" | "plain";

export type DiscoveryDocument = SnakeCasedProperties<
  Omit<ProviderConfig, "requirePKCEForPublicClients" | "requireState">
>;

export type ProviderConfig = {
  /**
   * The `issuer` is a case-sensitive URL using the HTTPS scheme that identifies your provider. REQUIRED
   *
   * - It MUST be a valid HTTPS URL (unless explicitly configured otherwise, e.g., `http://localhost` for dev/test).
   * - MUST NOT include a fragment (`#`) or query (`?`) component.
   * - The issuer URL must be the prefix of all the other endpoint URLs (`authorization_endpoint`, `token_endpoint`, etc.).
   * - It must be a URL with an absolute path (e.g., `https://server.example.com/`).
   * - Clients will validate that the issuer in ID Tokens matches this exact value.
   */
  issuer: string;

  /**
   * URL of the Authorization Server’s authorization endpoint. REQUIRED
   *
   * - Must exist and be non-empty.
   * - Must be HTTPS except localhost/loopback.
   * - Cannot contain fragment component `#`.
   * - Cannot contain search query component `?foo=bar`.
   * - Must start with the `issuer` URL.
   */
  authorizationEndpoint: string;

  /**
   * URL of the provider’s JSON Web Key Set document. REQUIRED
   *
   * Clients use it to fetch the public keys used to validate ID Tokens or request object signatures.
   *
   * - Typically uses HTTPS (required in production).
   * - Localhost/loopback exceptions allowed for dev/test.
   * - Must be a valid absolute URI.
   * - Must not contain a fragment `#`.
   * - Must not contain search query component `?foo=bar`.
   * - Must start with the `issuer` URL.
   */
  jwksUri: string;

  /**
   * URL of the provider’s token endpoint. REQUIRED
   *
   * Clients send authorization codes, refresh tokens, or other credentials here to obtain tokens.
   *
   * - Typically uses HTTPS (required in production).
   * - Localhost/loopback exceptions allowed for dev/test.
   * - Must be a valid absolute URI.
   * - Must not contain a fragment `#`.
   * - Must not contain search query component `?foo=bar`.
   * - Must start with the `issuer` URL.
   */
  tokenEndpoint: string;

  /**
   * URL of the provider’s UserInfo Endpoint. OPTIONAL, but required if the `openid` scope is supported.
   *
   * Clients use this endpoint to retrieve claims (e.g., `name`, `email`) about the authenticated user using an access token.
   *
   * - Must be a valid absolute URI.
   * - Must not contain a fragment (`#`).
   * - Must not contain search query component `?foo=bar`.
   * - Should use HTTPS (except localhost/loopback).
   */
  userinfoEndpoint?: string;
  registrationEndpoint?: string;
  scopesSupported?: ScopesSupported[];
  responseTypesSupported: ResponseTypesSupported[];
  subjectTypesSupported: SubjectTypesSupported[];
  idTokenSigningAlgValuesSupported: IdTokenSigningAlgValuesSupported[];
  responseModesSupported?: ResponseModesSupported[];
  grantTypesSupported?: GrantTypesSupported[];
  tokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported[];
  claimsSupported?: ClaimsSupported[];
  codeChallengeMethodsSupported?: CodeChallengeMethodsSupported[];
  requirePKCEForPublicClients?: boolean;
  requireState?: boolean;
};

export type AuthorizationRequest = z.infer<typeof AuthorizationRequestSchema>;

export type FlowType = "hybrid" | "authorization_code" | "implicit";
