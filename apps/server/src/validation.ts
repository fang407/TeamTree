import { z } from "zod";

export function validateRequest({
  params,
  body,
}: {
  params?: z.ZodType;
  body?: z.ZodType;
}) {
  return async (request: {
    params: unknown;
    body: unknown;
  }) => {
    if (params) {
      request.params = params.parse(request.params);
      console.log('validation params pass i guess')
    }

    if (body) {
      request.body = body.parse(request.body);
      console.log('validation body pass i guess')
    }
  };
}