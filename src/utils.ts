/**
 * Shared types and utilities
 */

/**
 * Props type that holds user information passed to MCP agent
 * The Hevy API key is stored encrypted in the session and decrypted by the auth middleware.
 */
export type Props = {
  hevyApiKey: string; // Decrypted Hevy API key (from session or X-Hevy-API-Key header)
  baseUrl?: string; // Base URL of the worker
};
