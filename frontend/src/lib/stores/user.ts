import { writable, derived } from 'svelte/store';

export type User = {
    id: number;
    username: string;
    email: string;
    role: string;
};

export const user = writable<User | null>(null);

export const isLoggedIn = derived(user, ($user) => $user !== null);

export function setUser(u: User) {
    user.set(u);
}

export function clearUser() {
    user.set(null);
}