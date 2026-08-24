import { IRouter } from '../../../../src/core/server';
import { API_ROOT } from '../../common';
import { defineAlertRoutes } from './alerts';
import { defineCommentRoutes } from './comments';
import { defineCaseRoutes } from './cases';
import { defineFilterRoutes } from './filters';
import { defineAiRoutes } from './ai';
import { defineUserRoutes } from './users';
import { defineReportRoutes } from './reports';

export function defineRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/example`,
      validate: false,
    },
    async (context, request, response) => {
      return response.ok({ body: { time: new Date().toISOString() } });
    }
  );

  defineAlertRoutes(router);
  defineCommentRoutes(router);
  defineCaseRoutes(router);
  defineFilterRoutes(router);
  defineAiRoutes(router);
  defineUserRoutes(router);
  defineReportRoutes(router);
}
