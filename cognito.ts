import { AuthFlowType, CognitoIdentityProviderClient, InitiateAuthCommand, RespondToAuthChallengeCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { JwtExpiredError } from "aws-jwt-verify/error";
import { createSrpSession, signSrpSession, wrapAuthChallenge, wrapInitiateAuth } from "cognito-srp-helper";

import type { InitiateAuthCommandInput, RespondToAuthChallengeCommandInput } from "@aws-sdk/client-cognito-identity-provider";
import type { CognitoAccessTokenPayload, CognitoIdTokenPayload } from "aws-jwt-verify/jwt-model";

/**
 * Configuration for connecting to AWS Cognito User Pool
 */
interface CognitoConfig {
  /** The unique identifier of your Cognito User Pool */
  userPoolId: string;

  /** The app client ID that's authorized to call Cognito APIs */
  clientId: string;

  /** AWS region where your Cognito User Pool is hosted */
  region: string;

  /** Function to obtain a cookie, added here so Cognito works on server and client */
  getCookie: (name: string) => Promise<string | undefined>;

  /** Function to set a cookie, added here so Cognito works on server and client */
  setCookie: (name: string, value: string, options: { expires: number }) => Promise<void>;

  /** Function to remove a cookie, added here so Cognito works on server and client */
  removeCookie: (name: string) => Promise<void>;
}

/**
 * Represents the authentication tokens returned after successful login
 */
interface CognitoTokens {
  /** JWT token containing user identity information */
  idToken: string;
  /** JWT token for accessing web services */
  accessToken: string;
  /** Long-lived token used to get new access tokens */
  refreshToken: string;
  /** Time in seconds until the tokens expire */
  expiresIn: number;
}

/**
 * Represents an authenticated user session with AWS Cognito.
 * This session contains everything needed to verify a user's identity and permissions,
 * similar to how a driver's license contains both identification and driving privileges.
 */
interface CognitoSession {
  /**
   * Raw JWT tokens used for API authentication.
   * Like a digital key card, these tokens prove the user's identity to our services.
   */
  tokens: CognitoTokens;

  /**
   * Decoded identity information from the ID token.
   * Contains verified user profile data like email, name, and phone number -
   * similar to the personal information section of an ID card.
   */
  idTokenPayload: CognitoIdTokenPayload;

  /**
   * Decoded authorization information from the access token.
   * Defines what the user is allowed to do, like user groups and permissions -
   * similar to how a license specifies which types of vehicles someone can drive.
   */
  accessTokenPayload: CognitoAccessTokenPayload;
}

/**
 * User credentials required for authentication
 */
interface LoginCredentials {
  /** User's email address */
  username: string;

  /** User's password */
  password: string;
}

let cognitoConfig: CognitoConfig | null = null;
let cognitoClient: CognitoIdentityProviderClient | null = null;
let jwtVerifier: ReturnType<typeof CognitoJwtVerifier.create> | null = null;
let getCookie: (name: string) => Promise<string | undefined>;
let setCookie: (name: string, value: string, options: { expires: number }) => Promise<void>;
let removeCookie: (name: string) => Promise<void>;

// Cookie names based on Amplify's naming convention
const getCookieNames = (clientId: string, username: string) => ({
  idToken: `CognitoIdentityServiceProvider.${clientId}.${username}.idToken`,
  accessToken: `CognitoIdentityServiceProvider.${clientId}.${username}.accessToken`,
  refreshToken: `CognitoIdentityServiceProvider.${clientId}.${username}.refreshToken`,
  lastUser: `CognitoIdentityServiceProvider.${clientId}.LastAuthUser`,
});

/**
 * Initializes the authentication system with your AWS Cognito configuration.
 * This must be called before any other authentication operations.
 *
 * @example
 * ```ts
 * configureCognito({
 *   userPoolId: 'us-east-1_xxxxxx',
 *   clientId: 'abcdef123456',
 *   region: 'us-east-1',
 *   getCookie: (name: string) => Cookies.get(name),
 *   setCookie: (name: string, value: string, options: { expires: number }) => Cookies.set(name, value, options),
 *   removeCookie: (name: string) => Cookies.remove(name),
 * });
 * ```
 *
 * @param config - AWS Cognito configuration details
 */
export const configureCognito = (config: CognitoConfig): void => {
  cognitoConfig = config;
  cognitoClient = new CognitoIdentityProviderClient({ region: config.region });
  jwtVerifier = CognitoJwtVerifier.create({
    userPoolId: config.userPoolId,
    clientId: config.clientId,
    tokenUse: "access",
  });

  getCookie = config.getCookie;
  setCookie = config.setCookie;
  removeCookie = config.removeCookie;
};

/**
 * Securely stores authentication tokens in browser cookies.
 * Uses Amplify's cookie naming convention for compatibility.
 *
 * @param tokens - The authentication tokens to store
 * @param username - User's email address
 */
const storeTokens = async (tokens: CognitoTokens, username: string): Promise<void> => {
  if (!cognitoConfig) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  const cookieNames = getCookieNames(cognitoConfig.clientId, username);
  const oneHour = 1 / 24;
  const thirtyDays = 30;

  await setCookie(cookieNames.idToken, tokens.idToken, { expires: oneHour });
  await setCookie(cookieNames.accessToken, tokens.accessToken, { expires: oneHour });
  await setCookie(cookieNames.refreshToken, tokens.refreshToken, { expires: thirtyDays });
  await setCookie(cookieNames.lastUser, username, { expires: thirtyDays });
};

/**
 * Retrieves stored authentication tokens from browser cookies.
 *
 * @returns Object containing the stored tokens and username if found
 */
const getStoredTokens = async (): Promise<{ tokens: Partial<CognitoTokens>; username: string | null }> => {
  if (!cognitoConfig) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  const username = await getCookie(`CognitoIdentityServiceProvider.${cognitoConfig.clientId}.LastAuthUser`);
  if (!username) {
    return { tokens: {}, username: null };
  }

  const cookieNames = getCookieNames(cognitoConfig.clientId, username);

  return {
    tokens: {
      idToken: await getCookie(cookieNames.idToken),
      accessToken: await getCookie(cookieNames.accessToken),
      refreshToken: await getCookie(cookieNames.refreshToken),
    },
    username,
  };
};

/**
 * Authenticates a user using Secure Remote Password (SRP) protocol.
 * This provides a secure way to log in without sending the password directly over the network.
 * Instead, it uses a cryptographic proof to verify the password, making it resistant to
 * man-in-the-middle attacks and password interception.
 *
 * The function handles the complete SRP authentication flow:
 * 1. Initiates the auth challenge with Cognito
 * 2. Computes the password verifier
 * 3. Responds to the challenge
 * 4. Stores the resulting tokens in cookies
 *
 * @example
 * ```ts
 * try {
 *   const tokens = await login({
 *     username: 'user@example.com',
 *     password: 'userPassword123'
 *   });
 *   // User is now logged in and can access protected resources
 * } catch (error) {
 *   // Handle specific error cases:
 *   // - Invalid credentials
 *   // - Network issues
 *   // - Account locked/disabled
 * }
 * ```
 *
 * @param credentials - User's login credentials
 * @param credentials.username - Email address used for registration
 * @param credentials.password - User's password (never sent directly to server)
 * @returns Promise<CognitoTokens> - Authentication tokens for accessing protected resources
 * @throws {Error} When login fails due to invalid credentials, network issues, or configuration problems
 */
export const login = async (credentials: LoginCredentials): Promise<CognitoTokens> => {
  // Ensure the authentication system is properly configured before proceeding
  if (!cognitoConfig || !cognitoClient) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  try {
    // Initialize the SRP authentication process
    // For email-based login, we use the raw password as AWS Cognito expects
    const srpSession = createSrpSession(
      credentials.username,
      credentials.password,
      cognitoConfig.userPoolId,
      false // Email-based login requires unhashed password
    );

    // Begin the authentication challenge with AWS Cognito
    // This step establishes the secure channel for password verification
    const initiateAuthParams: InitiateAuthCommandInput = {
      ClientId: cognitoConfig.clientId,
      AuthFlow: AuthFlowType.USER_SRP_AUTH,
      AuthParameters: {
        USERNAME: credentials.username,
        SRP_A: srpSession.largeA, // Public key for secure exchange
      },
    };

    // Wrap the auth parameters with SRP protocol requirements
    const wrappedInitiateAuth = wrapInitiateAuth(srpSession, initiateAuthParams);
    const initiateAuthCommand = new InitiateAuthCommand(wrappedInitiateAuth);
    const initiateAuthResponse = await cognitoClient.send(initiateAuthCommand);

    // Verify we received the necessary challenge parameters
    // USER_ID_FOR_SRP is crucial for completing the authentication
    if (!initiateAuthResponse.ChallengeParameters?.USER_ID_FOR_SRP) {
      throw new Error("Missing required USER_ID_FOR_SRP challenge parameter");
    }

    // Ensure we're in the correct authentication step
    if (!initiateAuthResponse.ChallengeName || initiateAuthResponse.ChallengeName !== "PASSWORD_VERIFIER") {
      throw new Error("Unexpected challenge name");
    }

    // Generate the cryptographic proof that we know the password
    // This step creates the signature without exposing the password
    const signedSession = signSrpSession(srpSession, initiateAuthResponse);

    // Complete the authentication by providing the password proof
    const respondToAuthParams: RespondToAuthChallengeCommandInput = {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: cognitoConfig.clientId,
      ChallengeResponses: {
        USERNAME: initiateAuthResponse.ChallengeParameters.USER_ID_FOR_SRP,
        TIMESTAMP: signedSession.timestamp,
        PASSWORD_CLAIM_SECRET_BLOCK: signedSession.secret,
        PASSWORD_CLAIM_SIGNATURE: signedSession.passwordSignature,
      },
    };

    // Send the final authentication proof to AWS Cognito
    const wrappedAuthChallenge = wrapAuthChallenge(signedSession, respondToAuthParams);
    const respondToAuthCommand = new RespondToAuthChallengeCommand(wrappedAuthChallenge);
    const respondToAuthResponse = await cognitoClient.send(respondToAuthCommand);

    // Ensure we received all required tokens for a successful authentication
    if (
      !respondToAuthResponse.AuthenticationResult?.IdToken ||
      !respondToAuthResponse.AuthenticationResult?.AccessToken ||
      !respondToAuthResponse.AuthenticationResult?.RefreshToken ||
      !respondToAuthResponse.AuthenticationResult?.ExpiresIn
    ) {
      throw new Error("Invalid authentication result");
    }

    // Package the authentication tokens for use in the application
    const tokens: CognitoTokens = {
      idToken: respondToAuthResponse.AuthenticationResult.IdToken,
      accessToken: respondToAuthResponse.AuthenticationResult.AccessToken,
      refreshToken: respondToAuthResponse.AuthenticationResult.RefreshToken,
      expiresIn: respondToAuthResponse.AuthenticationResult.ExpiresIn,
    };

    // Store tokens securely for future requests
    // This enables automatic session management
    await storeTokens(tokens, initiateAuthResponse.ChallengeParameters.USER_ID_FOR_SRP);

    return tokens;
  } catch (error) {
    // Log the error for debugging but don't expose internal details to the user
    console.error("Login Error:", error);
    throw new Error(`Login failed: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
};

/**
 * Maintains an active user session by obtaining new access tokens using a refresh token.
 * This allows users to stay logged in without re-entering credentials, similar to how
 * social media apps keep you logged in across browser restarts.
 *
 * @param refreshToken - Long-lived token from previous successful authentication
 * @returns Promise<CognitoTokens> - New set of authentication tokens
 * @throws {Error} When token refresh fails, requiring user to log in again
 */
const refreshTokens = async (refreshToken: string): Promise<CognitoTokens> => {
  // Verify authentication system is ready
  if (!cognitoConfig || !cognitoClient) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  // Prepare the token refresh request
  const params: InitiateAuthCommandInput = {
    AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
    ClientId: cognitoConfig.clientId,
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
    },
  };

  try {
    // Request new tokens from AWS Cognito
    const command = new InitiateAuthCommand(params);
    const response = await cognitoClient.send(command);

    // Verify we received valid tokens
    if (!response.AuthenticationResult?.IdToken || !response.AuthenticationResult?.AccessToken || !response.AuthenticationResult?.ExpiresIn) {
      throw new Error("Invalid refresh result");
    }

    // Return new tokens while preserving the original refresh token
    return {
      idToken: response.AuthenticationResult.IdToken,
      accessToken: response.AuthenticationResult.AccessToken,
      refreshToken: refreshToken, // Keep existing refresh token
      expiresIn: response.AuthenticationResult.ExpiresIn,
    };
  } catch (error) {
    // Token refresh failed - user needs to log in again
    throw new Error(`Token refresh failed: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
};

/**
 * Refreshes the user session by generating new tokens using the refresh token.
 * This function ensures that the user remains authenticated and can continue accessing protected resources.
 *
 * @param username - The username of the authenticated user
 * @param refreshToken - The long-lived refresh token used to generate new access tokens
 */
const refreshToken = async (username: string, refreshToken: string): Promise<CognitoSession> => {
  // Ensure authentication system is ready
  if (!cognitoConfig || !jwtVerifier) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  // Get new tokens using the refresh token
  const newTokens = await refreshTokens(refreshToken);
  await storeTokens(newTokens, username);

  // Verify the new tokens
  const accessTokenPayload = (await jwtVerifier.verify(newTokens.accessToken)) as CognitoAccessTokenPayload;
  const idTokenPayload = (await jwtVerifier.verify(newTokens.idToken, { tokenUse: "id" })) as CognitoIdTokenPayload;

  // Return refreshed session information
  return {
    tokens: newTokens,
    idTokenPayload,
    accessTokenPayload,
  };
};

/**
 * Retrieves and validates the current user session, automatically refreshing expired tokens.
 * This is the primary way to check if a user is logged in and get their profile information.
 *
 * Common uses:
 * - Checking if user is authenticated
 * - Getting user profile information
 * - Ensuring fresh tokens for API calls
 * - Implementing protected routes
 *
 * @example
 * ```ts
 * try {
 *   const session = await getSession();
 *   // User is logged in, use their information
 *   const userId = session.idTokenPayload.sub;
 *   const email = session.idTokenPayload.email;
 *   const groups = session.accessTokenPayload['cognito:groups'];
 * } catch (error) {
 *   // Redirect to login page
 * }
 * ```
 *
 * @returns Promise resolving to session details:
 *   - tokens: Raw JWT tokens for API authentication
 *   - idTokenPayload: User profile information
 *   - accessTokenPayload: User permissions and roles
 * @throws {Error} When no valid session exists or refresh fails
 */
export const getSession = async (): Promise<CognitoSession> => {
  // Ensure authentication system is ready
  if (!cognitoConfig || !jwtVerifier) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  // Get stored session data
  const { tokens, username } = await getStoredTokens();

  // Check if we have all required session data
  if (!tokens.refreshToken || !username) {
    throw new Error("No active session found");
  }

  // Access or id token cookies no longer existe but we have a refresh token, so we generate new tokens
  if (!tokens.accessToken || !tokens.idToken) {
    return refreshToken(username, tokens.refreshToken);
  }

  try {
    // Verify tokens are valid and not expired
    const accessTokenPayload = (await jwtVerifier.verify(tokens.accessToken)) as CognitoAccessTokenPayload;
    const idTokenPayload = (await jwtVerifier.verify(tokens.idToken, { tokenUse: "id" })) as CognitoIdTokenPayload;

    // Return verified session information
    return {
      tokens: {
        idToken: tokens.idToken,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: accessTokenPayload.exp - Math.floor(Date.now() / 1000),
      },
      idTokenPayload,
      accessTokenPayload,
    };
  } catch (error) {
    // Handle expired tokens by attempting a refresh
    if (error instanceof JwtExpiredError || (error instanceof Error && error.message.includes("expired"))) {
      // Get new tokens using the refresh token
      const newTokens = await refreshTokens(tokens.refreshToken);
      await storeTokens(newTokens, username);

      // Verify the new tokens
      const accessTokenPayload = (await jwtVerifier.verify(newTokens.accessToken)) as CognitoAccessTokenPayload;
      const idTokenPayload = (await jwtVerifier.verify(newTokens.idToken, { tokenUse: "id" })) as CognitoIdTokenPayload;

      // Return refreshed session information
      return {
        tokens: newTokens,
        idTokenPayload,
        accessTokenPayload,
      };
    }
    throw error;
  }
};

/**
 * Logs out the user from the current device/browser.
 * This removes the local session data without invalidating sessions on other devices.
 *
 * The function:
 * 1. Removes local session cookies
 * 2. Clears stored tokens
 *
 * @example
 * ```ts
 * await logout();
 * // User is now logged out on this device
 * // Redirect to login page
 * ```
 */
export const logout = async (): Promise<void> => {
  // Verify authentication system is ready
  if (!cognitoConfig) {
    throw new Error("Cognito is not configured. Call configureCognito first.");
  }

  // Get current session data
  const { username } = await getStoredTokens();

  // Remove local session data
  if (username) {
    const cookieNames = getCookieNames(cognitoConfig.clientId, username);
    await removeCookie(cookieNames.idToken);
    await removeCookie(cookieNames.accessToken);
    await removeCookie(cookieNames.refreshToken);
    await removeCookie(cookieNames.lastUser);
  }
};
