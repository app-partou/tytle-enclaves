import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      // Resolve @tytle-enclaves/shared to source (dist not built locally; native addon mocked)
      '@tytle-enclaves/shared': path.resolve(__dirname, '../shared/src/index.ts'),
      // The Rust addon is built only in Docker; a test that needs it mocks it (shared/src/__tests__/helpers/fakeEnclaveIo.ts).
      '@tytle-enclaves/native': path.resolve(__dirname, '../shared/src/__tests__/helpers/nativeStub.ts'),
    },
  },
});
