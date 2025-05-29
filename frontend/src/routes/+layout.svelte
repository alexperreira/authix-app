<script lang="ts">
	import '../app.css';
	import { goto } from '$app/navigation';
	import { clearUser, isLoggedIn, setUser } from '$lib/stores/user';
	import { onMount } from 'svelte';
	import type { User } from '$lib/stores/user';
	import { apiGet } from '$lib/api';

	let { children } = $props();

	type AuthUserResponse = User | { error: string };

	onMount(async () => {
		const token = localStorage.getItem('authix_token');
		if (!token) return;

		const res = (await apiGet('/auth/me', token)) as AuthUserResponse;

		if (!res || 'error' in res) {
			console.warn('Invalid token or failed auth:', res?.error);
			localStorage.removeItem('authix_token');
			return;
		}

		setUser(res);
	});

	function logout() {
		localStorage.removeItem('authix_token');
		clearUser();
		goto('/login');
	}
</script>

<nav class="flex justify-between bg-gray-900 p-4 text-white">
	<div class="text-lg font-bold">Authix</div>
	<div class="flex items-center gap-4">
		{#if !$isLoggedIn}
			<a href="/login" class="hover:underline">Login</a>
			<a href="/register" class="hover:underline">Register</a>
		{/if}
		<a href="/admin/users" class="hover:underline">Users</a>
		<a href="/admin/logs" class="hover:underline">Logs</a>
		<a href="/reset" class="hover:underline">Reset</a>
		{#if $isLoggedIn}
			<a href="/me" class="hover:underline">Me</a>
			<button onclick={logout} class="text-red-400 hover:underline">Logout</button>
		{/if}
	</div>
</nav>

<main class="flex justify-center p-6">
	<div class="flex w-full max-w-2xl flex-col items-center justify-center">
		{@render children()}
	</div>
</main>
