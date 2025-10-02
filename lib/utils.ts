import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function isURLValid(urlToCheck: string) {
  try {
    const url = new URL(urlToCheck);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (error) {
    console.error(error);
    return false;
  }
}

export function getURIProtocol(str: string) {
  try {
    const url = new URL(str);
    return url.protocol;
  } catch (error) {
    console.error(error);
    return null;
  }
}

export function isHTTPS(urlToCheck: string) {
  try {
    const url = new URL(urlToCheck);
    return url.protocol === "https:";
  } catch (error) {
    console.error(error);
    return false;
  }
}

export function isLocalhostURI(urlToCheck: string) {
  try {
    const uri = new URL(urlToCheck);
    return uri.hostname === "127.0.0.1" || uri.hostname === "localhost" || uri.hostname === "::1";
  } catch (error) {
    console.error(error);
    return false;
  }
}

export function containsURIFragment(urlToCheck: string) {
  try {
    const uri = new URL(urlToCheck);
    const withHash = uri.hash !== "";

    return {
      withHash,
      fragment: uri.hash,
    };
  } catch (error) {
    console.error(error);
    return {
      withHash: false,
      fragment: undefined,
    };
  }
}

export function containsURISearch(urlToCheck: string) {
  try {
    const uri = new URL(urlToCheck);
    const withSearch = uri.search !== "";

    return {
      withSearch,
      search: uri.search,
    };
  } catch (error) {
    console.error(error);
    return {
      withSearch: false,
      search: undefined,
    };
  }
}

export function containsURIPath(urlToCheck: string) {
  try {
    const uri = new URL(urlToCheck);
    const withPath = uri.pathname !== "/" && uri.pathname !== "";

    return {
      withPath,
      path: uri.pathname,
    };
  } catch (error) {
    console.error(error);
    return {
      withPath: false,
      path: undefined,
    };
  }
}

/**
 * Normalizes a space-delimited string parameter (e.g., response_type, scope)
 * - Splits on whitespace
 * - Removes empties
 * - Sorts alphabetically to make order-insensitive
 * - Joins back with a single space
 */
export function normalizeSpaceDelimitedSet(rt: string): string {
  return rt
    .split(/\s+/) // split by spaces
    .map((s) => s.trim())
    .filter((s) => s !== "")
    .sort() // normalize order
    .join(" ");
}
