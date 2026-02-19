/**
 * Cryptographic Utilities
 * Provides constant-time comparison and other security primitives
 */

/**
 * Constant-time string comparison to prevent timing attacks
 * 
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal, false otherwise
 * 
 * Note: Always compares full length to prevent timing leaks
 */
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}

	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}

	return result === 0;
}

/**
 * Validates that a hex string is exactly the expected length
 * 
 * @param hexString - The hex string to validate
 * @param expectedBytes - Expected number of bytes (hex length = bytes * 2)
 * @returns True if valid, false otherwise
 */
export function isValidHexKey(hexString: string, expectedBytes: number): boolean {
	const expectedLength = expectedBytes * 2;
	
	if (hexString.length !== expectedLength) {
		return false;
	}

	// Check if all characters are valid hex
	return /^[0-9a-fA-F]+$/.test(hexString);
}

/**
 * Validates input string length
 * 
 * @param input - String to validate
 * @param maxLength - Maximum allowed length
 * @returns True if valid, false otherwise
 */
export function isValidLength(input: string, maxLength: number): boolean {
	return input.length > 0 && input.length <= maxLength;
}
