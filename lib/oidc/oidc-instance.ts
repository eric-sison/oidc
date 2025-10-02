import { createEnv } from "@/helpers/createEnv";
import { ProviderConfigBuilder } from "@/lib/oidc/provider-builder";
import { ProviderService } from "@/lib/oidc/provider-service";
import { AuthorizationService } from "./authorization";
import { ClientService } from "./client-service";

export class ProviderInstance {
  private static instance: ProviderInstance;

  private readonly providerService: ProviderService;
  private readonly clientService: ClientService;
  private readonly authorizationService: AuthorizationService;

  private constructor() {
    const env = createEnv();

    const config = new ProviderConfigBuilder()
      .withIssuer(env.BETTER_AUTH_URL)
      .withAuthorizationEndpoint(`${env.BETTER_AUTH_URL}/api/oidc/authorize`)
      .withTokenEndpoint(`${env.BETTER_AUTH_URL}/api/oidc/token`)
      .withJwksUri(`${env.BETTER_AUTH_URL}/api/oidc/.well-known/jwks.json`)
      .withUserinfoEndpoint(`${env.BETTER_AUTH_URL}/api/oidc/userinfo`)
      .withResponseTypesSupported(["code", "code id_token", "id_token"])
      .withSubjectTypesSupported(["public", "pairwise"])
      .withIdTokenSigningAlgValuesSupported(["RS256", "ES256"])
      .withScopesSupported(["openid", "profile", "email", "address", "phone"])
      .withResponseModesSupported(["query", "fragment", "form_post"])
      .withGrantTypesSupported(["authorization_code", "refresh_token"])
      .withTokenEndpointAuthMethodsSupported(["client_secret_basic", "client_secret_post", "private_key_jwt"])
      .withClaimsSupported(["sub"])
      .withCodeChallengeMethodsSupported(["S256", "plain"])
      .build();

    this.providerService = new ProviderService(config);
    this.clientService = new ClientService();
    this.authorizationService = new AuthorizationService(this.providerService, this.clientService);
  }

  public static init(): ProviderInstance {
    if (!ProviderInstance.instance) {
      ProviderInstance.instance = new ProviderInstance();
    }
    return ProviderInstance.instance;
  }

  public getProvider() {
    return this.providerService;
  }

  public getAuthorization() {
    return this.authorizationService;
  }
}
