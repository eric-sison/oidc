import { PgSelect, PgTable } from "drizzle-orm/pg-core";
import { count } from "drizzle-orm";
import { PaginationOptions } from "@/shared/types/common";
import db from "@/db/connection";

export const withPagination = async <T extends PgSelect>(
  pgTable: PgTable,
  qb: T,
  options?: PaginationOptions,
) => {
  const limit = options?.limit ?? 10;
  const page = options?.page ?? 1;
  const offset = (page - 1) * limit;

  const total = await db.select({ count: count() }).from(pgTable);

  return {
    query: qb.limit(limit).offset(offset),
    metadata: {
      itemsPerPage: limit,
      totalItems: total[0].count,
      currentPage: page,
      totalPages: Math.ceil(Number(total[0].count) / limit),
    },
  };
};
