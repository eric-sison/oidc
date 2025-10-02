import { DiscoveryDocument, OIDCErrorCode } from "@/shared/types/oidc";
import { OIDCError } from "./oidc-error";

interface ArrayValidationOptions {
  required?: string[];
  allowed?: string[];
  mustNotBeEmpty?: boolean;
  errorCode?: OIDCErrorCode;
}

export class ArrayValidator {
  /**
   * Validates that a value is a non-empty array of strings with optional constraints
   */
  public validateStringArray(
    name: keyof DiscoveryDocument,
    arr: unknown,
    options: ArrayValidationOptions = {},
  ): void {
    this.checkIsArrayAndNotEmpty(name, arr, options);

    const stringArray = arr as string[];

    this.checkAllStringsNonEmpty(name, stringArray);
    this.checkNoDuplicates(name, stringArray);

    if (options.required) {
      this.checkIncludes(name, stringArray, options.required);
    }

    if (options.allowed) {
      this.checkAllowedValuesOnly(name, stringArray, options.allowed);
    }
  }

  private checkIsArrayAndNotEmpty(
    name: keyof DiscoveryDocument,
    arr: unknown,
    options: ArrayValidationOptions,
  ): void {
    if (!Array.isArray(arr) || (options.mustNotBeEmpty && arr.length === 0)) {
      throw new OIDCError({
        error: options.errorCode ?? "invalid_request",
        error_description: `${name} must be a non-empty array of strings`,
        status_code: 400,
      });
    }
  }

  private checkAllStringsNonEmpty(name: keyof DiscoveryDocument, arr: string[]): void {
    if (!arr.every((s) => typeof s === "string" && s.trim() !== "")) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} must contain only non-empty strings`,
        status_code: 400,
      });
    }
  }

  private checkNoDuplicates(name: string, arr: string[]): void {
    const duplicates = arr.filter((item, index) => arr.indexOf(item) !== index);
    if (duplicates.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} contains duplicate values: [${[...new Set(duplicates)].join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private checkIncludes(name: string, arr: string[], required: string[]): void {
    const missing = required.filter((req) => !arr.includes(req));

    if (missing.length > 0) {
      throw new OIDCError({
        error: "invalid_request",
        error_description: `${name} must include: [${missing.join(", ")}]`,
        status_code: 400,
      });
    }
  }

  private checkAllowedValuesOnly(name: string, arr: string[], allowed: string[]): void {
    for (const value of arr) {
      if (!allowed.includes(value)) {
        throw new OIDCError({
          error: "unsupported_response_type",
          error_description: `Invalid ${name} value: ${value}. Allowed values: ${allowed.join(", ")}`,
          status_code: 400,
        });
      }
    }
  }
}
