<script lang="ts">
	import { apiPost } from '$lib/api';
	import { goto } from '$app/navigation';
	// import { join } from 'path';

	type RegisterResponse = {
		message?: string;
		error?: string;
	};

	let username = '';
	let email = '';
	let password = '';
	let error = '';
	let success = '';

	const register = async () => {
		error = '';
		success = '';

		const res = (await apiPost('/auth/register', {
			username,
			email,
			password
		})) as RegisterResponse;

		if (res.message) {
			success = 'Registration successful! Redirecting to login...';
			setTimeout(() => goto('/login'), 1500);
		} else {
			error = res.error || 'Registration  failed';
		}
	};
</script>

<h1 class="mb-4 text-xl font-bold">Register</h1>
<form on:submit|preventDefault={register} class="flex max-w-sm flex-col gap-4">
	<input type="text" class="w-md rounded border p-2" bind:value={username} placeholder="Username" />
	<input type="email" class="w-md rounded border p-2" bind:value={email} placeholder="Email" />
	<input
		type="password"
		class="w-md rounded border p-2"
		bind:value={password}
		placeholder="Password"
	/>
	<button type="submit" class="w-md rounded bg-green-600 px-4 py-2 text-white">Register</button>
	{#if error}
		<p class="text-red-600">{error}</p>
	{:else if success}
		<p class="text-blue-600">{success}</p>
	{/if}
</form>
