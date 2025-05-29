<script lang="ts">
	import { apiGet } from '$lib/api';
	import { onMount } from 'svelte';

	type Log = {
		id: number;
		event: string;
		createdAt: string;
	};

	let logs: Log[] = [];
	let error = '';

	onMount(async () => {
		const token = localStorage.getItem('authix_token') || '';
		const res = (await apiGet('/auth/admin/logs', token)) as { logs?: Log[]; error?: string };

		if (res.logs) {
			logs = res.logs;
		} else {
			error = res.error || 'Failed to fetch logs.';
		}
	});
</script>

<h1 class="mb-4 text-xl font-bold">Log Entries</h1>
{#if error}
	<p class="text-red-600">{error}</p>
{:else if logs.length === 0}
	<p>No logs available.</p>
{:else}
	<table class="w-full table-auto border">
		<thead class="bg-gray-200">
			<tr>
				<th class="border px-4 py-2">ID</th>
				<th class="border px-4 py-2">Event</th>
				<th class="border px-4 py-2">Created</th>
			</tr>
		</thead>
		<tbody>
			{#each logs as log}
				<tr class="border-t">
					<td class="border px-4 py-2">{log.id}</td>
					<td class="border px-4 py-2">{log.event}</td>
					<td class="border px-4 py-2">{new Date(log.createdAt).toLocaleString()}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}
