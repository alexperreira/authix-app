<script lang="ts">
	import { apiPost } from '$lib/api';
	import { onMount } from 'svelte';

	let email = '';
	let resetToken = '';
	let newPassword = '';
	let result = '';

	const requestToken = async () => {
		result = '';
		const res = (await apiPost('/auth/request-password-reset', { email })) as {
			message?: string;
			resetToken?: string;
			error?: string;
		};
		result = res.message || res.error || '';
		if (res.resetToken) resetToken = res.resetToken;
	};

	const resetPassword = async () => {
		result = '';
		const res = (await apiPost('/auth/reset-password', { token: resetToken, newPassword })) as {
			message?: string;
			error?: string;
		};
		result = res.message || res.error || 'Something went wrong';
	};
</script>

<h1 class="mb-4 text-xl font-bold">Password Reset</h1>
<div class="flex max-w-md flex-col gap-4">
	<h2 class="font-semibold">Step 1: Request Reset Token</h2>
	<input
		type="text"
		class="w-md rounded border p-2"
		bind:value={email}
		placeholder="Email Address"
	/>
	<button on:click={requestToken} class="rounded bg-blue-500 px-4 py-2 text-white"
		>Request Token</button
	>

	<h2 class="mt-6 font-semibold">Step 2: Enter Token & New Password</h2>
	<input
		type="text"
		class="w-md rounded border p-2"
		bind:value={resetToken}
		placeholder="Reset Token"
	/>
	<input
		type="password"
		class="w-md rounded border p-2"
		bind:value={newPassword}
		placeholder="New Password"
	/>
	<button on:click={resetPassword} class="rounded bg-green-600 px-4 py-2 text-white"
		>Reset Password</button
	>
	{#if result}
		<p class="font-medium text-blue-600">{result}</p>
	{/if}
</div>
