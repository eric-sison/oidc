import z from "zod";
import { SnakeCasedProperties } from "./common";
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

export const CODE_CHALLENGE_METHODS = ["plain", "S256"] as const;

export const SUBJECT_TYPES = ["public", "pairwise"] as const;

export const RESPONSE_MODES = ["query", "fragment", "form_post"] as const;

export const RESPONSE_TYPES = [
  "code",
  "id_token",
  "token",
  "token id_token",
  "code id_token",
  "code token",
  "code id_token token",
] as const;

export const ID_TOKEN_SIGNING_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "PS384",
  "PS512",
  "HS256",
  "HS384",
  "HS512", // some OPs support HMAC
  "none", // allowed but dangerous
] as const;

export const STANDARD_GRANT_TYPES = [
  "authorization_code",
  "implicit",
  "refresh_token",
  "client_credentials",
] as const;

export const TOKEN_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "client_secret_jwt",
  "private_key_jwt",
  "tls_client_auth",
  "self_signed_tls_client_auth",
  "none",
] as const;

export const CLAIMS_SUPPORTED = [
  "sub",
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "email",
  "email_verified",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "phone_number",
  "phone_number_verified",
  "address",
  "updated_at",
] as const;

export type ScopesSupported = "openid" | "profile" | "email" | "address" | "phone" | "offline_access";
export type ResponseTypesSupported = (typeof RESPONSE_TYPES)[number];
export type SubjectTypesSupported = (typeof SUBJECT_TYPES)[number];
export type IdTokenSigningAlgValuesSupported = (typeof ID_TOKEN_SIGNING_ALGS)[number];
export type ResponseModesSupported = (typeof RESPONSE_MODES)[number];
export type GrantTypesSupported = (typeof STANDARD_GRANT_TYPES)[number];
export type TokenEndpointAuthMethodsSupported = (typeof TOKEN_AUTH_METHODS)[number];
export type ClaimsSupported = (typeof CLAIMS_SUPPORTED)[number];
export type CodeChallengeMethodsSupported = (typeof CODE_CHALLENGE_METHODS)[number];

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

  /**
   * URL of the provider’s endpoint for dynamic client registration. OPTIONAL.
   *
   * Allows clients to register dynamically with the provider.
   *
   * Returns client credentials and metadata.
   *
   * - Must be a valid absolute URI.
   * - Must not contain a fragment (`#`).
   * - Should use HTTPS (except localhost/loopback).
   * - Must not include query parameters in discovery.
   */
  registrationEndpoint?: string;

  /**
   * JSON array containing the OAuth 2.0 scopes the server supports. Recommended, but not strictly required.
   *
   * Lets clients know which scopes they can request (e.g., `openid`, `profile`, `email`, `offline_access`).
   *
   * - Must be a JSON array of strings. Each string is a scope name.
   * - Recommended to include the `openid` scope.
   * - No duplicates – optional best practice.
   */
  scopesSupported?: ScopesSupported[] | string[];

  /**
   * JSON array containing a list of the OAuth 2.0 response_type values that the OP supports. REQUIRED.
   *
   * The order of values in the response_type parameter does not matter and has no impact on processing.
   *
   * Tells clients which authorization flows the OP supports.
   *
   * `code` → Authorization Code Flow
   *
   * `id_token` → Implicit Flow (ID Token only)
   * 
   * `token` → OAuth2 Implicit Flow (Access Token only, not OIDC by itself)

   * `id_token token` → OIDC Implicit Flow (ID Token + Access Token)

   * `code id_token` → Hybrid Flow

   * `code token` → Hybrid Flow

   * `code id_token token` → Hybrid Flow

   * - Must exist and be a non-empty array.
   * - Array of strings only.
   * - Duplicates – not allowed (throw error).
   * - At least code – strongly recommended (most OIDC servers must support Authorization Code Flow).
   * 
   */
  responseTypesSupported: ResponseTypesSupported[] | string[];

  /**
   * Each value indicates the subject identifier types supported.
   *
   * At least one value must be present.
   *
   * - `public` - Most common, required by spec to support at least this.
   * - `pairwise` - Ooptional, for per-client pseudonymous subject identifiers.
   * - Must be a non-empty array of strings.
   * - Must only contain values from the allowed set: `public`, `pairwise`.
   * - No duplicates allowed.
   */
  subjectTypesSupported: SubjectTypesSupported[] | string[];

  /**
   * JSON array of JWA signing algorithms the OP supports for id_token (alg in JWS header).
   *
   * - Must be a non-empty array of strings.
   * - Must contain "RS256" (required by spec).
   * - Each value must be a valid JWA alg identifier.
   * - No duplicates allowed.
   */
  idTokenSigningAlgValuesSupported: IdTokenSigningAlgValuesSupported[] | string[];

  /**
   * Optional in discovery, but recommended.
   *
   * If omitted, the default values are: `query`, `fragment`
   *
   * Additional value `form_post` is strongly recommended if supported.
   */
  responseModesSupported?: ResponseModesSupported[] | string[];

  /**
   * Allowed values come from OAuth 2.0 + extensions. Common: `authorization_code` | `implicit` | `refresh_token` | `client_credentials`
   *
   * - If omitted → default to ["authorization_code", "implicit"].
   * - Must be a non-empty array of strings if present.
   * - Must contain at least one recognized grant type.
   * - Duplicates not allowed.
   */
  grantTypesSupported?: GrantTypesSupported[] | string[];

  /**
   * Defines the supported client authentication methods at the Token Endpoint.
   *
   * Common values: `client_secret_basic` | `client_secret_post` | `client_secret_jwt` | `private_key_jwt` | `tls_client_auth` | `self_signed_tls_client_auth` | `none`
   *
   * - If omitted → default to `["client_secret_basic"]`.
   * - Must be a non-empty array of strings if present.
   * - Each entry must be one of the registered authentication methods
   * - No duplicates allowed.
   */
  tokenEndpointAuthMethodsSupported?: TokenEndpointAuthMethodsSupported[] | string[];

  /**
   * Each entry names a Claim the provider MAY support in ID Tokens, UserInfo, or via claims parameter.
   *
   * - If omitted → it’s allowed (unlike some others).
   * - If present → must be a non-empty array of strings.
   * - Every value must be a non-empty string.
   * - Must include "sub".
   * - Duplicates are not allowed.
   */
  claimsSupported?: ClaimsSupported[] | string[];

  /**
   * If omitted, the AS/OP must assume only "plain" is supported.
   *
   * Allowed values: `S256` | `plain`
   *
   * If the Authorization Server supports PKCE, it must support at least "plain". Supporting "S256" is RECOMMENDED.
   *
   * - If undefined → treat as ["plain"].
   * - If present → must be a non-empty array of strings.
   * - Each value must be one of `plain` or `S256`.
   * - No duplicates allowed.
   * - Strong recommendation: must include `S256`. If not, throw a warning (but not necessarily an error).
   */
  codeChallengeMethodsSupported?: CodeChallengeMethodsSupported[] | string[];
};

export type AuthorizationRequest = z.infer<typeof AuthorizationRequestSchema>;

export type FlowType = "hybrid" | "authorization_code" | "implicit";
