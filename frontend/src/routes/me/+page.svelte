<script lang="ts">
	import { apiGet } from '$lib/api';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { setUser, user } from '$lib/stores/user';

	type Me = {
		id: number;
		username: string;
		email: string;
		role: string;
	};

	let error = '';

	onMount(async () => {
		const token = localStorage.getItem('access_token');
		if (!token) {
			goto('/login');
			return;
		}

		const res = (await apiGet('/auth/me', token)) as Me & { error?: string };

		if ('error' in res) {
			error = res.error || 'Unauthorized';
		} else {
			setUser(res);
		}
	});
</script>

<h1 class="mb-4 text-xl font-bold">My Profile</h1>
{#if error}
	<p class="text-red-600">{error}</p>
{:else if $user}
	<div class="max-w-md rounded border bg-gray-100 p-4">
		<p><strong>ID:</strong> {$user.id}</p>
		<p><strong>Username:</strong> {$user.username}</p>
		<p><strong>Email:</strong> {$user.email}</p>
		<p><strong>Role:</strong> {$user.role}</p>
	</div>
{/if}
