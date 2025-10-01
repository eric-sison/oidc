export type SnakeToCamel<S extends string> = S extends `${infer Head}_${infer Tail}`
  ? `${Head}${Capitalize<SnakeToCamel<Tail>>}`
  : S;

// Transform snake cased fields into camel cased fields
export type CamelCasedProperties<T> = {
  [K in keyof T as SnakeToCamel<Extract<K, string>>]: T[K];
};

// Convert camelCase string to snake_case
export type CamelToSnake<S extends string> = S extends `${infer Head}${infer Tail}`
  ? Tail extends Uncapitalize<Tail>
    ? `${Lowercase<Head>}${CamelToSnake<Tail>}`
    : `${Lowercase<Head>}_${CamelToSnake<Tail>}`
  : S;

// Transform camel cased fields into snake cased fields
export type SnakeCasedProperties<T> = {
  [K in keyof T as CamelToSnake<Extract<K, string>>]: T[K];
};

// Make certain fields of an object as partial
export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type PaginationOptions = {
  limit?: number;
  page?: number;
};

export type PaginatedResult<T> = {
  data: T[];
  metadata: {
    itemsPerPage: number;
    currentPage: number;
    totalItems: number;
    totalPages: number;
  };
};
