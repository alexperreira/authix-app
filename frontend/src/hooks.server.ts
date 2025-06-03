import type { Handle } from '@sveltejs/kit';

export const handle: Handle = async ({ event, resolve }) => {
    const response = await resolve(event, {
        filterSerializedResponseHeaders(name) {
            return name === 'content-type';
        },
    });

    response.headers.set(
        'Content-Security-Policy',
        [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "connect-src 'self' http://localhost:3000",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "font-src 'self' https: data:",
            "form-action 'self'",
            "script-src-attr 'none'",
            "upgrade-insecure-requests"
        ].join('; ')
    );

    return response;
};