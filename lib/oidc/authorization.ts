import { AuthorizationRequest, ResponseTypesSupported } from "@/shared/types/oidc";
import { OIDCError } from "./oidc-error";
import { ProviderService } from "./oidc-provider";
import { normalizeSpaceDelimitedSet } from "../utils";
import { ClientService } from "./client-service";

type ArrayValidationOptions = {
  requiredValues?: string[]; // must include
  allowedValues: string[]; // must be a subset of these
};

export class AuthorizationService {
  constructor(
    private readonly providerService: ProviderService,
    private readonly clientService: ClientService,
  ) {}

  public validateRequest(authorizationRequest: AuthorizationRequest) {
    this.validateResponseType(authorizationRequest.response_type);
    this.validateScope(authorizationRequest.scope);
  }

  private validateResponseType(responseType: string) {
    const responseTypesSupported = this.providerService.responseTypesSupported;

    // Make sure response_type is not missing
    if (!responseType) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing response_type parameter",
        status_code: 400,
      });
    }

    // Detect unsupported response_type
    const normalized = normalizeSpaceDelimitedSet(responseType);
    if (!responseTypesSupported.includes(normalized as ResponseTypesSupported)) {
      throw new OIDCError({
        error: "unsupported_response_type",
        error_description: `response_type must be one of: [${responseTypesSupported.join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private validateScope(scope: string) {
    const scopesSupported = this.providerService.scopesSupported as string[];

    if (!scope) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: "Missing 'scope' parameter",
        status_code: 400,
      });
    }

    const normalized = normalizeSpaceDelimitedSet(scope);
    const scopes = normalized.split(" ");
    const duplicates = scopes.filter((s, i) => scopes.indexOf(s) !== i);

    // Must contain openid
    if (!scopes.includes("openid")) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `The 'scope' parameter must include openid`,
        status_code: 400,
      });
    }

    // Detect duplicates
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Duplicate scope values not allowed: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }

    // Detect unsupported scopes
    const invalid = scopes.filter((s) => !scopesSupported.includes(s));
    if (invalid.length > 0) {
      throw new OIDCError({
        error: "invalid_scope",
        error_description: `Invalid scope(s): [${invalid.join(", ")}]. Allowed scopes: [${scopesSupported.join(", ")}]`,
        status_code: 400,
      });
    }
  }
}
