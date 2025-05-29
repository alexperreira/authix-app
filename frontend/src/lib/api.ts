export const API_URL = 'http://localhost:3000';

export const apiPost = async (
    path: string,
    body: object,
    token?: string
): Promise<unknown> => {
    const res = await fetch(`${API_URL}${path}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify(body)
    });

    return res.json();
};

export const apiGet = async (
    path: string,
    token: string
): Promise<unknown> => {
    const res = await fetch(`${API_URL}${path}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return res.json();
};