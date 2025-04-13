// Used to access requestContext.h3v1 below
import "grafserv/h3/v1";
// Used to access args.contextValue?.pgSettings below
import "@dataplan/pg/adaptors/pg";

import { Kind, OperationTypeNode } from "graphql";

import { getSession } from "./index";

import type { GraphileConfig } from "graphile-config";
import type { FieldNode, OperationDefinitionNode } from "graphql";

/**
 * Adds Cognito authentication to the GraphQL context so that requests are authenticated prior to being executed.
 *
 * Only getting the schema is not authenticated, so that introspection queries can be run without authentication.
 */
export const GraphileCognitoPreset: GraphileConfig.Preset = {
  grafast: {
    /**
     * Establishes the security context for each GraphQL request by integrating
     * AWS Cognito authentication with PostgreSQL row-level security.
     *
     * @param {Object} requestContext - The incoming request context from the client
     * @param {Object} requestContext.h3v1 - H3 framework specific request details
     * @param {Object} args - Additional arguments passed to the context function
     * @param {Object} [args.contextValue] - Existing context values to preserve
     * @returns {Promise<Object>} Context object containing PostgreSQL settings and user claims
     *
     * Business Value:
     * - Ensures data access is restricted to authorized users only
     * - Enables row-level security based on user identity
     * - Maintains security context across the entire request lifecycle
     * - Allows for fine-grained access control in database queries
     */
    context: async (requestContext, args) => {
      // Extract the raw HTTP request from the H3 framework context
      const req = requestContext.h3v1?.event.node.req;

      // Check if the document contains an introspection query
      const isSchemaQuery = args.document?.definitions?.some(
        (def): def is OperationDefinitionNode =>
          def.kind === Kind.OPERATION_DEFINITION &&
          def.operation === OperationTypeNode.QUERY &&
          def.selectionSet.selections.some((selection): selection is FieldNode => selection.kind === Kind.FIELD && (selection.name.value === "__schema" || selection.name.value === "__type"))
      );

      // We allow to run introspection queries without authentication
      //TODO We might want to make this configurable
      if (isSchemaQuery) {
        return { pgSettings: args.contextValue?.pgSettings };
      }

      // If no request is present, then this is likely a server side requests (SSR)
      if (!req) {
        return { pgSettings: args.contextValue?.pgSettings };
      }

      // Retrieve the user's authenticated session from AWS Cognito
      const { idTokenPayload } = await getSession();

      // Transform Cognito token claims into PostgreSQL-compatible settings
      // This enables row-level security policies to access user information
      const claims: Record<string, string> = {};
      for (const [key, value] of Object.entries(idTokenPayload)) {
        claims[`jwt.claims.${key}`] = value as string;
      }

      // Construct the security context that will be available to resolvers
      // and PostgreSQL row-level security policies
      return {
        pgSettings: {
          ...args.contextValue?.pgSettings,
          ...claims,
        },
      };
    },
  },
};
