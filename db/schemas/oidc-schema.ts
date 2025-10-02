import {
  ClaimsSupported,
  CodeChallengeMethodsSupported,
  GrantTypesSupported,
  IdTokenSigningAlgValuesSupported,
  ResponseModesSupported,
  ResponseTypesSupported,
  ScopesSupported,
  SubjectTypesSupported,
  TokenEndpointAuthMethodsSupported,
} from "@/shared/types/oidc";
import { jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema, createUpdateSchema } from "drizzle-zod";
import z from "zod";

export const providerConfig = pgTable("provider_config", {
  id: uuid("id").defaultRandom().primaryKey(),
  issuer: text("issuer").unique().notNull(),
  jwksUri: text("jwks_uri").unique().notNull(),
  tokenEndpoint: text("token_endpoint").notNull(),
  userinfoEndpoint: text("userinfo_endpoint"),
  responseTypesSupported: jsonb("response_types_supported").$type<ResponseTypesSupported[]>().notNull(),
  subjectTypesSupported: jsonb("subject_types_supported").$type<SubjectTypesSupported[]>().notNull(),
  scopesSupported: jsonb("scopes_supported").$type<ScopesSupported[]>().default(["openid"]),
  idTokenSigningAlgValuesSupported: jsonb("id_token_signing_alg_values_supported")
    .$type<IdTokenSigningAlgValuesSupported[]>()
    .notNull(),
  registrationEndpoint: text("registration_endpoint"),
  responseModesSupported: jsonb("response_modes_supported")
    .$type<ResponseModesSupported[]>()
    .default(["query", "fragment"]),
  grantTypesSupported: jsonb("grant_types_supported")
    .$type<GrantTypesSupported[]>()
    .default(["authorization_code"]),
  tokenEndpointAuthMethodsSupported: jsonb("token_endpoint_auth_methods_suported")
    .$type<TokenEndpointAuthMethodsSupported[]>()
    .default(["client_secret_basic"]),
  claimsSupported: jsonb("claims_supported").$type<ClaimsSupported[]>().default(["sub"]),
  codeChallengeMethodsSupported: jsonb("code_challenge_methods_supported")
    .$type<CodeChallengeMethodsSupported[]>()
    .default(["S256"]),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .defaultNow()
    .notNull()
    .$onUpdate(() => new Date()),
});

export const SelectProviderConfigSchema = createSelectSchema(providerConfig);
export const CreateProviderConfigSchema = createInsertSchema(providerConfig).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const UpdateProviderConfigSchema = createUpdateSchema(providerConfig).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type SelectProviderConfig = z.infer<typeof SelectProviderConfigSchema>;
export type CreateProviderConfig = z.infer<typeof CreateProviderConfigSchema>;
export type UpdateProviderConfig = z.infer<typeof UpdateProviderConfigSchema>;
