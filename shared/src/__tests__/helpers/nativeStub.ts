/**
 * Test stand-in for `@tytle-enclaves/native` (the napi addon: vsock sockets and the /dev/nsm ioctl).
 *
 * The real addon is compiled inside the enclave images for Linux only, so every package's vitest config
 * aliases the module here. A test that reaches the addon mocks it (`vi.mock('@tytle-enclaves/native')`);
 * anything that reaches this file instead throws, so a forgotten mock fails loudly instead of touching
 * a socket. The shape mirrors the napi-generated `native/index.d.ts`.
 */

function notInTests(name: string): never {
  throw new Error(`@tytle-enclaves/native.${name} is not available in tests: mock '@tytle-enclaves/native'`);
}

export function nsmRequest(_request: Buffer): Buffer {
  return notInTests('nsmRequest');
}

export function vsockConnectAsync(_cid: number, _port: number, _timeoutSecs?: number | null): Promise<VsockStream> {
  return notInTests('vsockConnectAsync');
}

export class VsockListener {
  static bind(_port: number): VsockListener {
    return notInTests('VsockListener.bind');
  }
  accept(): VsockStream {
    return notInTests('VsockListener.accept');
  }
  acceptAsync(): Promise<VsockStream> {
    return notInTests('VsockListener.acceptAsync');
  }
  close(): void {
    notInTests('VsockListener.close');
  }
}

export class VsockStream {
  static connect(_cid: number, _port: number): VsockStream {
    return notInTests('VsockStream.connect');
  }
  read(_size: number): Buffer {
    return notInTests('VsockStream.read');
  }
  write(_data: Buffer): number {
    return notInTests('VsockStream.write');
  }
  close(): void {
    notInTests('VsockStream.close');
  }
  get fd(): number {
    return notInTests('VsockStream.fd');
  }
  get peerCid(): number {
    return notInTests('VsockStream.peerCid');
  }
  get peerPort(): number {
    return notInTests('VsockStream.peerPort');
  }
}
