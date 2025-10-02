import { ProviderService } from "./oidc-provider";
import { OIDC_CONFIG } from "@/shared/constants/oidc-config";

export class ProviderInstance {
  private static instance: ProviderInstance;

  private readonly providerService: ProviderService;
  // private readonly authorizationService: AuthorizationService;

  private constructor() {
    this.providerService = new ProviderService(OIDC_CONFIG);
    //this.authorizationService = new AuthorizationService();
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

  // public getAuthorization() {
  //   return this.authorizationService;
  // }
}
