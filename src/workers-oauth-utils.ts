/**
 * OAuth Provider Utilities
 * Handles approval dialogs and client approval tracking
 */

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

/**
 * Renders the OAuth approval dialog HTML
 * Shown to users when authorizing a new OAuth client
 */
export function renderApprovalDialog(params: {
	clientId: string;
	redirectUri: string;
	state: string;
	scope: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	userLogin: string;
	userName: string;
	authorizeEndpoint: string;
}): string {
	const {
		clientId,
		redirectUri,
		state,
		scope,
		codeChallenge,
		codeChallengeMethod,
		userLogin,
		userName,
		authorizeEndpoint,
	} = params;

	const safeClientId = escapeHtml(clientId);
	const safeRedirectUri = escapeHtml(redirectUri);
	const safeState = escapeHtml(state);
	const safeScope = escapeHtml(scope);
	const safeCodeChallenge = escapeHtml(codeChallenge ?? "");
	const safeCodeChallengeMethod = escapeHtml(codeChallengeMethod ?? "");
	const safeUserLogin = escapeHtml(userLogin);
	const safeUserName = escapeHtml(userName);
	const safeAuthorizeEndpoint = escapeHtml(authorizeEndpoint);

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Authorize Application</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.container {
			background: white;
			border-radius: 12px;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
			max-width: 500px;
			width: 100%;
			padding: 40px;
		}
		.header {
			text-align: center;
			margin-bottom: 30px;
		}
		.header h1 {
			color: #333;
			font-size: 24px;
			margin-bottom: 10px;
		}
		.user-info {
			background: #f7f9fc;
			border-radius: 8px;
			padding: 15px;
			margin-bottom: 25px;
		}
		.user-info p {
			color: #555;
			font-size: 14px;
			margin-bottom: 5px;
		}
		.user-info strong {
			color: #333;
		}
		.permissions {
			margin-bottom: 25px;
		}
		.permissions h2 {
			font-size: 16px;
			color: #333;
			margin-bottom: 15px;
		}
		.permission-item {
			background: #f7f9fc;
			border-left: 3px solid #667eea;
			padding: 12px;
			margin-bottom: 10px;
			border-radius: 4px;
		}
		.permission-item p {
			color: #555;
			font-size: 14px;
			line-height: 1.5;
		}
		.client-info {
			background: #fff9e6;
			border-left: 3px solid #ffc107;
			padding: 12px;
			margin-bottom: 25px;
			border-radius: 4px;
		}
		.client-info p {
			color: #666;
			font-size: 13px;
			margin-bottom: 5px;
		}
		.client-info code {
			background: #f5f5f5;
			padding: 2px 6px;
			border-radius: 3px;
			font-family: monospace;
			font-size: 12px;
		}
		.actions {
			display: flex;
			gap: 10px;
			margin-top: 25px;
		}
		button {
			flex: 1;
			padding: 12px 24px;
			border: none;
			border-radius: 6px;
			font-size: 16px;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.2s;
		}
		.btn-approve {
			background: #667eea;
			color: white;
		}
		.btn-approve:hover {
			background: #5568d3;
			transform: translateY(-1px);
			box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
		}
		.btn-deny {
			background: #e0e0e0;
			color: #666;
		}
		.btn-deny:hover {
			background: #d0d0d0;
		}
		.footer {
			margin-top: 25px;
			text-align: center;
			color: #999;
			font-size: 12px;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔐 Authorize Application</h1>
		</div>

		<div class="user-info">
			<p><strong>Signed in as:</strong> ${safeUserName} (@${safeUserLogin})</p>
		</div>

		<div class="client-info">
			<p><strong>Client ID:</strong> <code>${safeClientId}</code></p>
			<p><strong>Redirect URI:</strong> <code>${safeRedirectUri}</code></p>
		</div>

		<div class="permissions">
			<h2>This application will be able to:</h2>
			<div class="permission-item">
				<p><strong>💪 Access your Hevy workout data</strong></p>
				<p>View and manage your workouts, routines, and exercise templates</p>
			</div>
			<div class="permission-item">
				<p><strong>🔑 Store your API key securely</strong></p>
				<p>Your Hevy API key will be encrypted and stored for your account</p>
			</div>
		</div>

		<form method="POST" action="${safeAuthorizeEndpoint}">
			<input type="hidden" name="client_id" value="${safeClientId}" />
			<input type="hidden" name="redirect_uri" value="${safeRedirectUri}" />
			<input type="hidden" name="state" value="${safeState}" />
			<input type="hidden" name="scope" value="${safeScope}" />
			<input type="hidden" name="code_challenge" value="${safeCodeChallenge}" />
			<input type="hidden" name="code_challenge_method" value="${safeCodeChallengeMethod}" />
			
			<div class="actions">
				<button type="submit" name="approve" value="true" class="btn-approve">
					Authorize
				</button>
				<button type="submit" name="approve" value="false" class="btn-deny">
					Deny
				</button>
			</div>
		</form>

		<div class="footer">
			<p>Hevy MCP Server - Multi-User OAuth</p>
		</div>
	</div>
</body>
</html>`;
}

/**
 * Parses the approval form submission
 */
export async function parseRedirectApproval(request: Request): Promise<{
	approved: boolean;
	clientId: string;
	redirectUri: string;
	state: string;
	scope: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
}> {
	const formData = await request.formData();

	return {
		approved: formData.get("approve") === "true",
		clientId: formData.get("client_id") as string,
		redirectUri: formData.get("redirect_uri") as string,
		state: formData.get("state") as string,
		scope: formData.get("scope") as string,
		codeChallenge: (formData.get("code_challenge") as string) || undefined,
		codeChallengeMethod: (formData.get("code_challenge_method") as string) || undefined,
	};
}

/**
 * Checks if a client has already been approved by the user
 * Stored in KV with key: `approval:{username}:{clientId}`
 */
export async function clientIdAlreadyApproved(
	kv: KVNamespace,
	username: string,
	clientId: string
): Promise<boolean> {
	const key = `approval:${username}:${clientId}`;
	const approval = await kv.get(key);
	return approval === "true";
}

/**
 * Stores client approval in KV
 */
export async function storeClientApproval(
	kv: KVNamespace,
	username: string,
	clientId: string
): Promise<void> {
	const key = `approval:${username}:${clientId}`;
	// Store for 1 year
	await kv.put(key, "true", { expirationTtl: 365 * 24 * 60 * 60 });
}

