import type { FastifyRequest } from "fastify";
import { z } from "zod";

export function validateRequest({
  params,
  body,
}: {
  params?: z.ZodType;
  body?: z.ZodType;
}) {
  return async (request: FastifyRequest) => {
    if (params) {
      request.params = params.parse(request.params);
      request.log.info(
        { method: request.method, url: request.url },
        "Request params validation passed");
    }

    if (body) {
      request.body = body.parse(request.body);
      request.log.info(
        { method: request.method, url: request.url },
        "Request body validation passed",
      );
    }
  };
}
