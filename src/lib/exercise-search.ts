/**
 * Exercise-template search.
 *
 * Pure filtering over a catalog of exercise templates so the tool handler can
 * stay thin (fetch + cache) and the matching logic stays easy to test.
 */

/** A trimmed exercise-template match returned by search. */
export interface ExerciseTemplateMatch {
	id?: string;
	title?: string;
	type?: string;
	primary_muscle_group?: string;
	is_custom: boolean;
}

/**
 * Case-insensitive substring match on the template title.
 *
 * @param templates - Full catalog of exercise templates
 * @param query - Text to look for in the title
 * @param limit - Maximum number of matches to return
 */
export function filterExerciseTemplates(
	templates: Array<Record<string, any>>,
	query: string,
	limit: number,
): ExerciseTemplateMatch[] {
	const normalized = query.trim().toLowerCase();
	if (normalized === "") return [];

	const matches: ExerciseTemplateMatch[] = [];
	for (const template of templates) {
		if (
			typeof template.title === "string" &&
			template.title.toLowerCase().includes(normalized)
		) {
			matches.push({
				id: template.id,
				title: template.title,
				type: template.type,
				primary_muscle_group: template.primary_muscle_group,
				is_custom: Boolean(template.is_custom),
			});
			if (matches.length >= limit) break;
		}
	}
	return matches;
}
