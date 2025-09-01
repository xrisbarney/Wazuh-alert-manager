import { CoreStart } from '../../../../src/core/public';

export class AlertsApiService {
  constructor(private http: CoreStart['http']) { }

  async fetchAlertCounts(query?: string) {
    try {
      const queryBody: any = {
        size: 0,
        aggs: {
          status_counts: {
            terms: {
              field: 'status',
              size: 10
            }
          }
        }
      };

      if (query) {
        queryBody.query = {
          query_string: {
            query: query,
            analyze_wildcard: true
          }
        };
      } else {
        queryBody.query = { match_all: {} };
      }

      const response = await this.http.post('/api/console/proxy', {
        query: {
          path: '/wazuh-alert-status/_search',
          method: 'GET',
        },
        body: JSON.stringify(queryBody),
      });
      return response;
    } catch (error) {
      console.error('Error fetching alert counts:', error);
      throw error;
    }
  }

  async fetchAlerts(query?: string, from: number = 0, size: number = 20) {
    try {
      const queryBody: any = {
        from,
        size,
        sort: [{ '@timestamp': { order: 'desc' } }],
      };

      if (query) {
        queryBody.query = {
          query_string: {
            query: query,
            analyze_wildcard: true
          }
        };
      } else {
        queryBody.query = { match_all: {} };
      }

      const response = await this.http.post('/api/console/proxy', {
        query: {
          path: '/wazuh-alert-status/_search',
          method: 'GET',
        },
        body: JSON.stringify(queryBody),
      });
      return response;
    } catch (error) {
      console.error('Error fetching alerts:', error);
      throw error;
    }
  }

  async updateAlertStatus(alertId: string, status: string) {
    try {
      const response = await this.http.post('/api/console/proxy', {
        query: {
          path: `/wazuh-alert-status/_update/${alertId}`,
          method: 'POST',
        },
        body: JSON.stringify({
          doc: {
            status,
            updated_at: new Date().toISOString()
          }
        }),
      });
      return response;
    } catch (error) {
      console.error('Error updating alert:', error);
      throw error;
    }
  }
}