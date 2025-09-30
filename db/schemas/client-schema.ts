import {
  GrantTypesSupported,
  ResponseTypesSupported,
  ScopesSupported,
  SubjectTypesSupported,
  TokenEndpointAuthMethodSupported,
} from "@/shared/types/oidc";
import { jsonb, pgTable, text, timestamp, unique, uuid, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema, createUpdateSchema } from "drizzle-zod";

export const relyingParties = pgTable(
  "relying_parties",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").defaultRandom().unique().notNull(),
    /**
     * Human-readable name for consent screens
     */
    name: varchar("client_name").unique().notNull(),
    description: varchar("client_description"),
    secret: text("client_secret").unique().notNull(),

    /**
     * URIs the OP can redirect to after auth.
     *
     * Array of HTTPS URIs (strings). Example: `["https://example.com/callback", "https://example.com/alt"]`.
     * @type string[]
     */
    redirectURIs: jsonb("redirect_uris").$type<string[]>().notNull(),

    /**
     * Which OIDC response types the client uses.
     *
     * Array of strings. Possible: `code`, `id_token`, `token`, or combos like `code id_token`, `code token`, `code id_token token`. Default if omitted: [`code`].
     * @type ResponseTypesSupported[]
     */
    responseTypes: jsonb("response_types").$type<ResponseTypesSupported[]>().notNull(),

    /**
     * Array of strings. Possible: `authorization_code`, `implicit`, `refresh_token`, `client_credentials`. Default if omitted: `[authorization_code]`.
     * @type GrantTypesSupported[]
     */
    grantTypes: jsonb("grant_types").$type<GrantTypesSupported[]>().notNull(),

    /**
     * One of: `client_secret_basic` (default), `client_secret_post`, `none`.
     * @type TokenEndpointAuthMethodSupported
     */
    tokenEndpointAuthMethod: varchar("token_endpoint_auth_methods")
      .$type<TokenEndpointAuthMethodSupported>()
      .notNull(),

    /**
     * URL for client homepage
     */
    clientURI: text("client_uri"),

    /**
     * Logo for consent screen
     */
    logoURI: text("logo_uri"),

    /**
     * Scopes client requests by default
     *
     * Must include `openid`. Example: `["openid" ,"profile", "email"]`.
     *
     * @type ScopesSupported[]
     */
    scopes: jsonb("allowed_scopes").$type<ScopesSupported[]>().notNull(),

    /**
     * Admin emails
     */
    contacts: jsonb("contacts").$type<string[]>(),

    /**
     * Terms of service page
     */
    tosURI: text("tos_uri"),

    /**
     * Privacy policy page
     */
    policyURI: text("policy_uri"),

    /**
     * Subject identifier type
     *
     * `public` (same sub for all RPs) or `pairwise` (per-sector unique sub). Default: `public`
     * @type SubjectTypesSupported
     */
    subjectType: varchar("subject_type").$type<SubjectTypesSupported>().default("public"),

    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull()
      .$onUpdate(() => new Date()),
  },
  (t) => [unique().on(t.id, t.clientId)],
);

export const SelectRelyingPartySchema = createSelectSchema(relyingParties);
export const CreateRelyingPartySchema = createInsertSchema(relyingParties).omit({
  id: true,
  clientId: true,
});
export const UpdateRelyingPartySchema = createUpdateSchema(relyingParties).omit({
  id: true,
  clientId: true,
});
