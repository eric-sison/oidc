import db from "@/db/connection";
import { accounts, sessions, users, verifications } from "@/db/schemas/auth-schema";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { openAPI } from "better-auth/plugins";

export const auth = betterAuth({
  plugins: [openAPI()],
  database: drizzleAdapter(db, {
    provider: "pg",
    usePlural: true,
    schema: {
      users,
      accounts,
      verifications,
      sessions,
    },
  }),

  user: {
    /**
     * Rename 'image' field to 'picture' - in compliance with openid connect standard claims.
     *  See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
     */
    fields: {
      image: "picture",
    },

    /**
     * Add openid connect standard claims.
     */
    additionalFields: {
      isActive: {
        type: "boolean",
        required: true,
      },

      givenName: {
        type: "string",
        required: true,
      },

      familyName: {
        type: "string",
        required: true,
      },

      middleName: {
        type: "string",
        required: false,
      },

      nickname: {
        type: "string",
        required: false,
      },

      preferredUsername: {
        type: "string",
        required: false,
      },

      profile: {
        type: "string",
        required: false,
      },

      website: {
        type: "string",
        required: false,
      },

      gender: {
        type: "string",
        required: false,
      },

      birthdate: {
        type: "date",
        required: false,
      },

      zoneinfo: {
        type: "string",
        required: false,
      },

      locale: {
        type: "string",
        required: false,
      },

      phoneNumber: {
        type: "string",
        required: false,
      },

      phoneNumberVerified: {
        type: "boolean",
        required: false,
      },

      address: {
        type: "string", // Just stringify the JSON object later
        required: false,
      },
    },
  },

  rateLimit: {
    window: 60,
    max: 10,
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // 1 day (every 1 day the session expiration is updated)
    cookieCache: {
      enabled: true,
      maxAge: 5 * 60, // 5 mins
    },
  },

  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
    requireEmailVerification: false,
    sendResetPassword: async ({ user, url }) => {
      // Add implementation
    },
  },

  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          return {
            data: {
              ...user,
              // Make sure that when image is an empty string, modify it to be of value NULL before inserting to the database
              image: user.image === "" ? null : user.image,
            },
          };
        },
      },
    },
  },

  trustedOrigins: [], // Add other hosts here

  advanced: {
    database: {
      generateId: false, // Handle the generation of ID's manually.
    },
    cookiePrefix: "erp",
  },
});

export type ServerSession = typeof auth.$Infer.Session;
