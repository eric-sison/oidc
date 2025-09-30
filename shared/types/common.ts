type SnakeToCamel<S extends string> = S extends `${infer Head}_${infer Tail}`
  ? `${Head}${Capitalize<SnakeToCamel<Tail>>}`
  : S;

// Transform snake cased fields into camel cased fields
export type CamelCasedProperties<T> = {
  [K in keyof T as SnakeToCamel<Extract<K, string>>]: T[K];
};

// Make certain fields of an object as partial
export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
