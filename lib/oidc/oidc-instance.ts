import { createEnv } from "@/helpers/createEnv";
import { ProviderConfigBuilder } from "@/lib/oidc/provider-builder";
import { ProviderService } from "@/lib/oidc/provider-service";
import { AuthorizationService } from "./authorization";
import { ClientService } from "./client-service";
import { FlowService } from "./flow-service";
import { AuthorizationValidatorService } from "./authorization-validator";

export class ProviderInstance {
  private static instance: ProviderInstance;

  private readonly providerService: ProviderService;
  private readonly clientService: ClientService;
  private readonly authorizationValidatorService: AuthorizationValidatorService;
  private readonly authorizationService: AuthorizationService;
  private readonly flowService: FlowService;

  private constructor() {
    const env = createEnv();

    const config = new ProviderConfigBuilder()
      .withIssuer(`${env.BETTER_AUTH_URL}`)
      .withAuthorizationEndpoint(`${env.BETTER_AUTH_URL}/api/oidc/authorize`)
      .withTokenEndpoint(`${env.BETTER_AUTH_URL}/api/oidc/token`)
      .withJwksUri(`${env.BETTER_AUTH_URL}/api/oidc/.well-known/jwks.json`)
      .withUserinfoEndpoint(`${env.BETTER_AUTH_URL}/userinfo`)
      .withResponseTypesSupported(["code", "code id_token", "id_token"])
      .withSubjectTypesSupported(["public", "pairwise"])
      .withIdTokenSigningAlgValuesSupported(["RS256", "ES256"])
      .withScopesSupported(["openid", "profile", "email", "address", "phone", "offline_access"])
      .withResponseModesSupported(["query"])
      .withGrantTypesSupported(["authorization_code", "refresh_token"])
      .withTokenEndpointAuthMethodsSupported(["client_secret_basic", "client_secret_post", "private_key_jwt"])
      .withClaimsSupported(["sub"])
      .withCodeChallengeMethodsSupported(["S256"])
      .build();

    this.providerService = new ProviderService(config);
    this.clientService = new ClientService();
    this.authorizationValidatorService = new AuthorizationValidatorService(
      this.providerService,
      this.clientService,
    );
    this.authorizationService = new AuthorizationService(this.authorizationValidatorService);
    this.flowService = new FlowService(this.authorizationService);
  }

  public static init(): ProviderInstance {
    if (!ProviderInstance.instance) {
      ProviderInstance.instance = new ProviderInstance();
    }
    return ProviderInstance.instance;
  }

  get provider() {
    return this.providerService;
  }

  get authorization() {
    return this.authorizationService;
  }

  get flow() {
    return this.flowService;
  }
}
