import { IRouter } from '../../../../src/core/server';
import { API_ROOT } from '../../common';
import { defineAlertRoutes } from './alerts';
import { defineCommentRoutes } from './comments';
import { defineCaseRoutes } from './cases';
import { defineFilterRoutes } from './filters';
import { defineAiRoutes } from './ai';
import { defineUserRoutes } from './users';
import { defineReportRoutes } from './reports';
import { defineAttackPathRoutes } from './attack_path';
import { defineRuleRoutes } from './rules';
import { defineSystemRoutes } from './system';
import { defineEvidenceRoutes } from './evidence';
import { defineIndicatorRoutes } from './indicators';
import { defineEnrichmentRoutes } from './enrichment';
import { defineAssetRoutes } from './assets';
import { defineAttachmentRoutes } from './attachments';
import { defineSlaRoutes } from './sla';
import { defineCaseTaskRoutes } from './case_tasks';
import { defineTaskListRoutes } from './task_lists';
import { defineNotificationRoutes } from './notifications';

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
  defineAttackPathRoutes(router);
  defineRuleRoutes(router);
  defineSystemRoutes(router);
  defineEvidenceRoutes(router);
  defineIndicatorRoutes(router);
  defineEnrichmentRoutes(router);
  defineAssetRoutes(router);
  defineAttachmentRoutes(router);
  defineSlaRoutes(router);
  defineCaseTaskRoutes(router);
  defineTaskListRoutes(router);
  defineNotificationRoutes(router);
}
