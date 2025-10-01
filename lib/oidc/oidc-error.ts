import { OIDCErrorCode, OIDCErrorParams } from "@/shared/types/oidc";

/**
 * @example
 *
 * // At token endpoint
 *  throw new OIDCError({
 *  error: "invalid_request",
 *  error_description: "Missing 'grant_type' parameter",
 *  });
 *
 *  // At authorization endpoint
 *  const err = new OIDCError({
 *  error: "login_required",
 *  state: "abc123",
 *  });
 *
 *  const redirectUri = `https://client.example.com/cb?${err.toQueryParams()}`;
 */
export class OIDCError extends Error {
  public readonly error: OIDCErrorCode;
  public readonly error_description?: string;
  public readonly error_uri?: string;
  public readonly state?: string;
  public readonly status_code?: number;

  constructor(params: OIDCErrorParams & { status_code?: number }) {
    super(params.error_description ?? params.error);
    this.name = "OIDCError";
    this.error = params.error;
    this.error_description = params.error_description;
    this.error_uri = params.error_uri;
    this.state = params.state;
    this.status_code = params.status_code;
  }

  /**
   * Returns error in JSON format (used for Token Endpoint responses)
   */
  toJSON() {
    const json: Record<string, string> = { error: this.error };
    if (this.error_description) json.error_description = this.error_description;
    if (this.error_uri) json.error_uri = this.error_uri;
    return json;
  }

  /**
   * Returns error in query string or fragment format
   * (used for Authorization Endpoint redirect responses)
   */
  toQueryParams() {
    const params = new URLSearchParams({ error: this.error });
    if (this.error_description) params.set("error_description", this.error_description);
    if (this.error_uri) params.set("error_uri", this.error_uri);
    if (this.state) params.set("state", this.state);
    return params.toString();
  }
}
