import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      // Resolve @tytle-enclaves/shared to source (dist not built locally; native addon mocked)
      '@tytle-enclaves/shared': path.resolve(__dirname, '../shared/src/index.ts'),
    },
  },
});
