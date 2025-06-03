<script lang="ts">
	import { apiPost } from '$lib/api';
	import { goto } from '$app/navigation';

	let username = '';
	let password = '';
	let error = '';
	let success = '';

	type LoginResponse = {
		accessToken?: string;
		refreshToken?: string;
		user?: {
			id: number;
			username: string;
			email: string;
			role: string;
		};
		error?: string;
	};

	const login = async () => {
		error = '';
		success = '';

		const res = (await apiPost('/auth/login', { username, password })) as LoginResponse;

		if (res.error) {
			error = res.error;
		} else if (res.accessToken && res.user) {
			localStorage.setItem('access_token', res.accessToken);
			success = 'Login successful! Redirecting...';
			setTimeout(() => goto('/me'), 1000);
		} else {
			error = 'Unexpected error occurred.';
		}
	};
</script>

<h1 class="mb-4 text-xl font-bold">Login</h1>
<form on:submit|preventDefault={login} class="flex max-w-sm flex-col gap-4">
	<input type="text" class="w-md rounded border p-2" bind:value={username} placeholder="Username" />
	<input
		type="password"
		class="w-md rounded border p-2"
		bind:value={password}
		placeholder="Password"
	/>
	<button type="submit" class="w-md rounded bg-blue-600 px-4 py-2 text-white">Login</button>
	{#if error}
		<p class="text-red-600">{error}</p>
	{:else if success}
		<p class="font-medium text-blue-600">{success}</p>
	{/if}
</form>
