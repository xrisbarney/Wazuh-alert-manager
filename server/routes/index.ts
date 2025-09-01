import { IRouter } from '........srccoreserver';

export function defineRoutes(router: IRouter) {
  router.get(
    {
      path: '/api/wazuh_alert_manager/example',
      validate: false,
    },
    async (context, request, response) => {
      return response.ok({
        body: {
          time: new Date().toISOString(),
        },
      });
    }
  );
}
