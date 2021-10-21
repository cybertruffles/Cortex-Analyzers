# Cortex Analyzers
## Overview
Cortex Analyzers are used by [TheHive Project](https://thehive-project.org/)'s Cortex to process observables.

### Umbrella
[Cisco Umbrella](https://dashboard.umbrella.com) is a service offered by Cisco.

## Analyzer Required Configuration
### Umbrella
#### [Reporting v2](https://developer.cisco.com/docs/cloud-security/#reporting-v2-overview)
| Variable | Description | Required | 
|--- |--- |--- |
| organization_name | Display Name for organization | **Yes** |
| organization_id | Organization ID from Dashboard | **Yes** | 
| api_key | API Key from Umbrella Admin console | **Yes** | 
| api_secret | API Secret from Umbrella Admin console | **Yes** |
| query_limit | Limits each query by this amount | No |

#### [Investigate & Samples](https://developer.cisco.com/docs/cloud-security/#investigate-overview)
The defaults for `Safe` and `Suspicious` are 30 and 50, respectively.

| Variable | Description | Required | 
| --- | --- | --- |
| access_token | API Token from Investigate | **Yes** |
| risk_safe_limit | Max value for safe, i.e, green | No |
| risk_suspicious_limit | Highest value for suspicious, i.e., amber | No |
| sample_safe_limit | Max value for safe, i.e, green | No |
| sample_suspicious_limit | Highest value for suspicious, i.e., amber | No |
