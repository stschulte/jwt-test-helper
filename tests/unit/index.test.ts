import { describe, expect, it } from 'vitest';

import { Issuer } from '../../src/index.js';
import { Issuer as OriginalIssuer } from '../../src/issuer.js';

describe('index', () => {
  it('reexports issuer', () => {
    expect(Issuer).toBe(OriginalIssuer);
  });
});
