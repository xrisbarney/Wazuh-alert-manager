export interface WazuhAlertManagerPluginSetup { }
export interface WazuhAlertManagerPluginStart { }

export interface Alert {
  _id: string;
  _source: {
    agent: {
      ip: string;
      name: string;
      id: string;
    };
    manager: {
      name: string;
    };
    rule: {
      id: string;
      description: string;
      level: number;
    };
    '@timestamp': string;
    status: 'open' | 'in progress' | 'closed';
    [key: string]: any;
  };
}