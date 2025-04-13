## Cognito Auth

Simple Cognito with SRP and e-mail authentication without all of the bloat of the AWS library.

Currently it ONLY supports SRP with e-mail.

It also includes a helper preset (GraphileCognitoPreset) for Graphile that configures session checking prior to executing requests in Grafast.

This works nicely with @carvajalconsultants/headstart. It can be configured by adding `cognito.config.ts` at the root of your project:

```typescript
// cognito.config.ts
import { configureCognito } from "@carvajalconsultants/cognito";
import { getCookie, removeCookie, setCookie } from "@carvajalconsultants/headstart/cookies";

// Configure Cognito for client side use
configureCognito({
  userPoolId: "VALUEHERE",
  clientId: "VALUEHERE",
  region: "VALUEHERE",

  // Functions used to manage cookies on both the server AND the client.
  getCookie: (name: string) => getCookie(name),
  setCookie: (name: string, value: string, options) => setCookie(name, value, options),
  removeCookie: (name: string) => removeCookie(name),
});
```

This `cognito.config.ts` must then be included in both client and server files.

For example, when using Tanstack Start you would first create an authenticated route:

```typescript
import "~/cognito.config";

import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";

import { getSession } from "@carvajalconsultants/cognito";

const AuthLayout = () => (
  ...
);

export const Route = createFileRoute("/_authenticated")({
  component: AuthLayout,
  errorComponent: () => <div>Error</div>,
  beforeLoad: async () => {
    try {
      // If a valid session is not available, this throws an error which means the user cannot access the resource.
      await getSession();
    } catch {
      throw redirect({ to: "/auth/login" });
    }
  },
});
```

Now on a server only file, where you need to do authentication you must also call `cognito.config.ts`. A helper preset for Graphile is included, so if using that, you would do something like this:

```typescript
import "./cognito.config";

import { GraphileCognitoPreset } from "@carvajalconsultants/cognito/GraphileCognitoPreset";
import { GraphileCarvajalPreset } from "@carvajalconsultants/graphile";
import { makePgService } from "postgraphile/adaptors/pg";

import type { GraphileConfig } from "graphile-config";

/**
 * PostGraphile configuration preset that sets up a secure, performant GraphQL API
 * with AWS Cognito authentication integration.
 *
 * This configuration enables:
 * - Secure user authentication via AWS Cognito
 * - Real-time data updates through event streams
 * - Interactive GraphQL development environment
 * - Simplified database schema naming
 */
const preset: GraphileConfig.Preset = {
  extends: [GraphileCarvajalPreset, GraphileCognitoPreset],

  grafserv: {
    port: 5678,
    graphiql: true,
    watch: true,
    graphqlPath: "/api/graphql",
    eventStreamPath: "/api/graphql",
  },

  /**
   * Database connection configuration that specifies which schemas contain
   * our business logic and data models.
   *
   * - app_public: Contains publicly accessible database objects
   */
  pgServices: [
    makePgService({
      connectionString: process.env.POSTGRES_CONNECTION_STRING,

      schemas: ["app_public"],
    }),
  ],
};

export default preset;
```
