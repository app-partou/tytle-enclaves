import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    alias: {
      // The shared library from source (its dist is built only inside the image build).
      '@tytle-enclaves/shared': path.resolve(__dirname, '../shared/src/index.ts'),
      // The napi addon exists only in the Linux image builds; tests mock it, the stub throws if one forgets.
      '@tytle-enclaves/native': path.resolve(__dirname, '../shared/src/__tests__/helpers/nativeStub.ts'),
    },
  },
});
