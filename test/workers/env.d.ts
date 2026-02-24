// Type declarations for @cloudflare/vitest-pool-workers
// Source: https://developers.cloudflare.com/workers/testing/vitest-integration/write-your-first-test/
declare module "cloudflare:test" {
  interface ProvidedEnv {
    OAUTH_KV: KVNamespace;
    COOKIE_ENCRYPTION_KEY: string;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
  }
}
