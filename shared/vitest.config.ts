import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    alias: {
      // The napi addon (vsock sockets + the /dev/nsm ioctl) is compiled inside the enclave images for
      // Linux only. Tests mock it with vi.mock('@tytle-enclaves/native'); this alias only makes the
      // import resolvable, and the stub throws if a test reaches it without a mock.
      '@tytle-enclaves/native': path.resolve(__dirname, 'src/__tests__/helpers/nativeStub.ts'),
    },
  },
});
