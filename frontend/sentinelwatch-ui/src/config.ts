// Where the API lives. Local dev: http://127.0.0.1:8000. A deployed site sets VITE_API_URL
// at build time (the deploy files use "/api", served from the same address as the site).
export const API_URL: string = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
