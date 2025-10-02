import { createEnv } from "@/helpers/createEnv";
import { ProviderConfig } from "@/shared/types/oidc";

const env = createEnv();

export const OIDC_CONFIG: ProviderConfig = {
  // registrationEndpoint: `${env.BETTER_AUTH_URL}/api/oidc/registration`,
  issuer: env.BETTER_AUTH_URL,
  authorizationEndpoint: `${env.BETTER_AUTH_URL}/api/oidc/authorize`,
  jwksUri: `${env.BETTER_AUTH_URL}/api/oidc/.well-known/jwks.json`,
  tokenEndpoint: `${env.BETTER_AUTH_URL}/api/oidc/token`,
  userinfoEndpoint: `${env.BETTER_AUTH_URL}/api/oidc/userinfo`,
  idTokenSigningAlgValuesSupported: ["RS256"],
  grantTypesSupported: ["authorization_code"],
  scopesSupported: ["openid", "profile", "email", "address", "phone", "offline_access"],
  responseTypesSupported: ["code", "code id_token", "code token", "code id_token token"],
  subjectTypesSupported: ["public"],
  tokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
  codeChallengeMethodsSupported: ["S256"],
  claimsSupported: [
    "sub",
    "given_name",
    "middle_name",
    "family_name",
    "email",
    "email_verified",
    "address",
    "birthdate",
    "gender",
    "picture",
    "phone_number",
    "nickname",
    "phone_number_verified",
    "website",
  ],
};
