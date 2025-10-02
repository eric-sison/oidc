import { type CreateRelyingParty, type UpdateRelyingParty, relyingParties } from "@/db/schemas/client-schema";
import { type PaginationOptions } from "@/shared/types/common";
import { withPagination } from "@/helpers/paginate";
import { OIDCError } from "./oidc-error";
import { eq } from "drizzle-orm";
import db from "@/db/connection";

export class ClientService {
  /**
   *
   * @param options
   * @returns
   */
  public async getAllClients(options?: PaginationOptions) {
    const clients = db
      .select({
        clientId: relyingParties.clientId,
        name: relyingParties.name,
        description: relyingParties.description,
        subjectType: relyingParties.subjectType,
        clientURI: relyingParties.clientURI,
        logoURI: relyingParties.logoURI,
      })
      .from(relyingParties)
      .$dynamic();

    const result = await withPagination(relyingParties, clients.$dynamic(), options);
    const data = await result.query;

    return {
      data,
      ...result.metadata,
    };
  }

  /**
   *
   * @param clientId
   * @returns
   */
  public async getClientById(clientId: string) {
    const client = await db
      .select({
        clientId: relyingParties.clientId,
        name: relyingParties.name,
        description: relyingParties.description,
        subjectType: relyingParties.subjectType,
        redirectURIs: relyingParties.redirectURIs,
        responseTypes: relyingParties.responseTypes,
        grantTypes: relyingParties.grantTypes,
        scopes: relyingParties.scopes,
        tokenEndpointAuthMethod: relyingParties.tokenEndpointAuthMethod,
        clientURI: relyingParties.clientURI,
        logoURI: relyingParties.logoURI,
        tosURI: relyingParties.tosURI,
        policyURI: relyingParties.policyURI,
        contacts: relyingParties.contacts,
        createdAt: relyingParties.createdAt,
        updatedAt: relyingParties.updatedAt,
      })
      .from(relyingParties)
      .where(eq(relyingParties.clientId, clientId));

    if (!client.length) {
      throw new OIDCError({
        error: "unauthorized_client",
        error_description: "Unknown client",
        status_code: 401,
      });
    }

    return client[0];
  }

  /**
   *
   * @param createClientDTO
   * @returns
   */
  public async registerClient(createClientDTO: CreateRelyingParty) {
    const client = await db.insert(relyingParties).values(createClientDTO).returning({
      clientId: relyingParties.clientId,
      name: relyingParties.name,
      description: relyingParties.description,
      subjectType: relyingParties.subjectType,
      redirectURIs: relyingParties.redirectURIs,
      responseTypes: relyingParties.responseTypes,
      grantTypes: relyingParties.grantTypes,
      scopes: relyingParties.scopes,
      tokenEndpointAuthMethod: relyingParties.tokenEndpointAuthMethod,
      clientURI: relyingParties.clientURI,
      logoURI: relyingParties.logoURI,
      tosURI: relyingParties.tosURI,
      policyURI: relyingParties.policyURI,
      contacts: relyingParties.contacts,
      createdAt: relyingParties.createdAt,
      updatedAt: relyingParties.updatedAt,
    });

    return client[0];
  }

  /**
   *
   * @param clientId
   * @param updateClientDTO
   * @returns
   */
  public async updateClient(clientId: string, updateClientDTO: UpdateRelyingParty) {
    const client = await db
      .update(relyingParties)
      .set(updateClientDTO)
      .where(eq(relyingParties.clientId, clientId))
      .returning({
        clientId: relyingParties.clientId,
        name: relyingParties.name,
        description: relyingParties.description,
        subjectType: relyingParties.subjectType,
        redirectURIs: relyingParties.redirectURIs,
        responseTypes: relyingParties.responseTypes,
        grantTypes: relyingParties.grantTypes,
        scopes: relyingParties.scopes,
        tokenEndpointAuthMethod: relyingParties.tokenEndpointAuthMethod,
        clientURI: relyingParties.clientURI,
        logoURI: relyingParties.logoURI,
        tosURI: relyingParties.tosURI,
        policyURI: relyingParties.policyURI,
        contacts: relyingParties.contacts,
        createdAt: relyingParties.createdAt,
        updatedAt: relyingParties.updatedAt,
      });

    return client[0];
  }

  /**
   *
   * @param clientId
   * @returns
   */
  public async deleteClient(clientId: string) {
    const client = await db
      .delete(relyingParties)
      .where(eq(relyingParties.clientId, clientId))
      .returning({ clientId: relyingParties.clientId });

    return { clientId: client[0].clientId, deleteAt: new Date() };
  }
}
