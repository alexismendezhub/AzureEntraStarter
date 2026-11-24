// Must match AuthCookies.cs on the server. The refresh cookie itself is HttpOnly and never visible here.
export const XSRF_COOKIE_NAME = '__Host-aes_xsrf';
export const XSRF_HEADER_NAME = 'X-AES-XSRF-TOKEN';
/** Where a user lands after signing in when no return URL was requested. */
export const HOME_URL = '/';
/** The only role the sample administration page needs (an Entra app role value). */
export const ADMIN_ROLE = 'Admin';
