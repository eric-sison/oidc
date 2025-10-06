import { AuthorizationRequest, FlowType } from "@/shared/types/oidc";
import { AuthorizationService } from "./authorization";

export class FlowService {
  private flowType: FlowType | undefined;

  constructor(private readonly authorizationService: AuthorizationService) {}

  public initiateFlow(request: AuthorizationRequest, userId: string) {
    this.flowType = this.setFlowType(request.response_type);

    switch (this.flowType) {
      // authorization code flow
      case "authorization_code":
        return this.handleAuthorizationCodeFlow(request, userId);

      // implicit flow
      case "implicit":
        return this.handleImplicitFlow(request);

      // hybrid flow
      case "hybrid":
        return this.handleHybridFlow(request);

      // throw error
      default:
        throw new Error("response_type is not supported!");
    }
  }

  private async handleAuthorizationCodeFlow(authorizationRequest: AuthorizationRequest, userId: string) {
    const clientURI = new URL(authorizationRequest.redirect_uri);

    const authorizationCode = await this.authorizationService.createAuthorizationCode({
      client_id: authorizationRequest.client_id,
      redirect_uri: authorizationRequest.redirect_uri,
      scope: authorizationRequest.scope.split(" "),
      user_id: userId,
      code_challenge: authorizationRequest.code_challenge,
      code_challenge_method: authorizationRequest.code_challenge_method,
    });

    const params: Record<string, string> = {
      code: authorizationCode,
    };

    if (authorizationRequest.state) {
      params.state = authorizationRequest.state;
    }

    // Default to query
    clientURI.search = new URLSearchParams(params).toString();
    return clientURI;
  }

  private async handleImplicitFlow(request: AuthorizationRequest): Promise<URL> {
    // TODO: to be implemented
    // 1. Validate request
    // 2. Authenticate user
    // 3. Immediately issue id_token and/or access_token in fragment
    // 4. Redirect with `#id_token=...&access_token=...&state=...`
    return new URL("");
  }

  private async handleHybridFlow(request: AuthorizationRequest): Promise<URL> {
    // TODO: to be implemented
    // 1. Validate request
    // 2. Authenticate user
    // 3. Issue a mix of code + token or code + id_token or all three
    // 4. Redirect user with appropriate values in query or fragment
    return new URL("");
  }

  private setFlowType(responseType: string): FlowType {
    const parts = responseType.trim().split(/\s+/).sort();

    const isCode = parts.includes("code");
    const isToken = parts.includes("token");
    const isIdToken = parts.includes("id_token");

    if (isCode && (isToken || isIdToken)) {
      return "hybrid";
    }

    if (isCode) {
      return "authorization_code";
    }

    return "implicit";
  }
}
