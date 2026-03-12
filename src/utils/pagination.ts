// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/** A page of results with metadata about the full result set. */
export interface PaginatedResult<T> {
  readonly results: readonly T[];
  readonly total: number;
  readonly offset: number;
  readonly limit: number;
}

/**
 * Extract a page from a complete result array.
 *
 * @param items  - The full result set.
 * @param offset - Zero-based index of the first result to return.
 * @param limit  - Maximum number of results to return.
 * @returns A {@link PaginatedResult} containing the slice and total count.
 */
export function paginate<T>(items: readonly T[], offset: number, limit: number): PaginatedResult<T> {
  return {
    results: items.slice(offset, offset + limit),
    total: items.length,
    offset,
    limit,
  };
}
