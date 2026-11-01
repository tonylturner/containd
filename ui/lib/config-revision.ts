/** CAS acknowledges only the view that submitted the write. Never install an
 * old response beneath a newer read's revision. */
export function canAcknowledge(base: string | undefined, submitted: string | undefined, revision?: string): boolean {
  return base === submitted && !!revision;
}
