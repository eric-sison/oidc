import {
  getURIProtocol,
  isURLValid,
  isLocalhostURI,
  isHTTPS,
  containsURIPath,
  containsURIFragment,
  containsURISearch,
} from "@/lib/utils";
import { DiscoveryDocument, ValidateConfigURIOptions } from "@/shared/types/oidc";
import { OIDCError } from "./oidc-error";

export class URIValidator {
  constructor(private readonly issuer: string) {}

  /**
   * Validates a URI based on the provided options
   */
  public validateURI(
    uri: string | undefined,
    key: keyof Pick<
      DiscoveryDocument,
      | "issuer"
      | "authorization_endpoint"
      | "jwks_uri"
      | "token_endpoint"
      | "userinfo_endpoint"
      | "registration_endpoint"
    >,
    options: Partial<ValidateConfigURIOptions> = {},
  ): void {
    const safeUri = uri ?? "";

    const protocol = getURIProtocol(safeUri);
    const isValid = isURLValid(safeUri);
    const isLocalhost = isLocalhostURI(safeUri);
    const isSecured = isHTTPS(safeUri);
    const { withPath, path } = containsURIPath(safeUri);
    const { withHash, fragment } = containsURIFragment(safeUri);
    const { withSearch, search } = containsURISearch(safeUri);

    this.checkValidity(key, isValid, options.valid);
    this.checkRequired(key, uri, options.required);
    this.checkHTTPS(key, uri, isSecured, isLocalhost, protocol, options.httpsOnly);
    this.checkNoPath(key, withPath, path, options.noPath);
    this.checkNoFragment(key, withHash, fragment, options.noFragment);
    this.checkNoQuery(key, withSearch, search, options.noQuery);
    this.checkSameOrigin(key, uri, options.sameOrigin);
  }

  private checkValidity(key: string, isValid: boolean, shouldValidate?: boolean): void {
    if (shouldValidate && !isValid) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} must be a valid absolute URI`,
        status_code: 400,
      });
    }
  }

  private checkRequired(key: string, uri: string | undefined, required?: boolean): void {
    if (required && !uri) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `Missing required field: ${key}`,
        status_code: 400,
      });
    }
  }

  private checkHTTPS(
    key: string,
    uri: string | undefined,
    isSecured: boolean,
    isLocalhost: boolean,
    protocol: string | null,
    httpsOnly?: boolean,
  ): void {
    if (httpsOnly && !(!uri || isSecured || (isLocalhost && protocol === "http:"))) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} must use https, except for localhost/loopback`,
        status_code: 400,
      });
    }
  }

  private checkNoPath(key: string, withPath: boolean, path: string | undefined, noPath?: boolean): void {
    if (noPath && withPath) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} should not include a path. Use root URL as issuer. Got ${path}`,
        status_code: 400,
      });
    }
  }

  private checkNoFragment(
    key: string,
    withHash: boolean,
    fragment: string | undefined,
    noFragment?: boolean,
  ): void {
    if (noFragment && withHash) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} must not contain a fragment component. Got ${fragment}`,
        status_code: 400,
      });
    }
  }

  private checkNoQuery(
    key: string,
    withSearch: boolean,
    search: string | undefined,
    noQuery?: boolean,
  ): void {
    if (noQuery && withSearch) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} must not contain a search query component. Got ${search}`,
        status_code: 400,
      });
    }
  }

  private checkSameOrigin(key: string, uri: string | undefined, sameOrigin?: boolean): void {
    if (sameOrigin && uri && !uri.startsWith(this.issuer)) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${key} must be under the issuer URL`,
        status_code: 400,
      });
    }
  }
}
