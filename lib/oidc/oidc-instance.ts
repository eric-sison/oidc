import { AuthorizationService } from "./authorization";
import { ClientService } from "./client-service";
import { ProviderService } from "./oidc-provider";
import { OIDC_CONFIG } from "@/shared/constants/oidc-config";

export class ProviderInstance {
  private static instance: ProviderInstance;

  private readonly providerService: ProviderService;
  private readonly clientService: ClientService;
  private readonly authorizationService: AuthorizationService;

  private constructor() {
    this.providerService = new ProviderService(OIDC_CONFIG);
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
