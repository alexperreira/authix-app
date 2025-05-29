<script lang="ts">
	import { apiGet } from '$lib/api';
	import { onMount } from 'svelte';

	type User = {
		id: number;
		username: string;
		email: string;
		role: string;
	};

	let users: User[] = [];
	let error = '';

	onMount(async () => {
		const token = localStorage.getItem('authix_token') || '';
		const res = (await apiGet('/auth/admin/users', token)) as { users?: User[]; error?: string };

		if (res.users) {
			users = res.users;
		} else {
			error = res.error || 'Failed to fetch users';
		}
	});
</script>

<h1 class="mb-4 text-xl font-bold">User List</h1>
{#if error}
	<p class="text-red-600">{error}</p>
{:else if users.length === 0}
	<p>No users found.</p>
{:else}
	<table class="w-full table-auto border">
		<thead class="bg-gray-200">
			<tr>
				<th class="border px-4 py-2">ID</th>
				<th class="border px-4 py-2">Username</th>
				<th class="border px-4 py-2">Email</th>
				<th class="border px-4 py-2">Role</th>
			</tr>
		</thead>
		<tbody>
			{#each users as user}
				<tr class="border-t">
					<td class="border px-4 py-2">{user.id}</td>
					<td class="border px-4 py-2">{user.username}</td>
					<td class="border px-4 py-2">{user.email}</td>
					<td class="border px-4 py-2">{user.role}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}
