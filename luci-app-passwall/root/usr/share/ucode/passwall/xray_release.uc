'use strict';
export function latest_release(value) {
	if (type(value) != 'array') value = [value];
	let latest = null;
	for (let release in value) {
		if (type(release) != 'object' || release.draft || type(release.tag_name) != 'string' || !release.published_at) continue;
		if (latest == null || release.published_at > latest.published_at) latest = release;
	}
	return latest ?? {};
};
