// Minimal buffer shim: frida-java-bridge only uses Buffer inside mkdex (class
// generation), which this agent never calls. A stub is enough to satisfy the
// import so esbuild can bundle.
export const Buffer = globalThis.Buffer || class BufferStub {};
export default { Buffer };
