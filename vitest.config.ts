import { defineConfig } from 'vitest/config';
import { defineWorkersProject } from '@cloudflare/vitest-pool-workers/config';

export default defineConfig({
  test: {
    projects: [
      // Project 1: Node pool — existing tests
      {
        test: {
          name: 'node',
          globals: true,
          environment: 'node',
          setupFiles: ['./test/setup.ts'],
          include: ['test/**/*.test.ts'],
          exclude: ['test/workers/**', 'node_modules', 'dist'],
          coverage: {
            provider: 'v8',
            reporter: ['text', 'html', 'json'],
            exclude: [
              'test/**',
              'dist/**',
              '**/*.config.ts',
              '**/*.d.ts',
            ],
          },
        },
      },

      // Project 2: Workers pool — encryption and Workers runtime tests
      defineWorkersProject({
        test: {
          name: 'workers',
          include: ['test/workers/**/*.workers.test.ts'],
          poolOptions: {
            workers: {
              wrangler: {
                configPath: './wrangler.jsonc',
              },
              miniflare: {
                kvNamespaces: ['OAUTH_KV'],
                bindings: {
                  COOKIE_ENCRYPTION_KEY: 'a'.repeat(64),
                  GITHUB_CLIENT_ID: 'test-github-client-id',
                  GITHUB_CLIENT_SECRET: 'test-github-client-secret',
                },
              },
            },
          },
        },
      }),
    ],
  },
});
