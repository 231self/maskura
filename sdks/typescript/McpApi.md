# .McpApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMcpToken**](McpApi.md#createMcpToken) | **POST** /dashboard/api/mcp-tokens | Create an MCP bearer token (&#x60;s4m_...&#x60;). The plaintext token is returned once and only its hash is stored.
[**deleteMcpToken**](McpApi.md#deleteMcpToken) | **DELETE** /dashboard/api/mcp-tokens | Revoke an MCP bearer token.
[**getMcpTokens**](McpApi.md#getMcpTokens) | **GET** /dashboard/api/mcp-tokens | List MCP bearer tokens for the authenticated user (hashes only).


# **createMcpToken**
> McpTokenCreatedResponse createMcpToken(createMcpTokenRequest)


### Example


```typescript
import { createConfiguration, McpApi } from '';
import type { McpApiCreateMcpTokenRequest } from '';

const configuration = createConfiguration();
const apiInstance = new McpApi(configuration);

const request: McpApiCreateMcpTokenRequest = {
  
  createMcpTokenRequest: {
    expiresIn: 0,
    label: "label_example",
  },
};

const data = await apiInstance.createMcpToken(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **createMcpTokenRequest** | **CreateMcpTokenRequest**|  |


### Return type

**McpTokenCreatedResponse**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Created MCP token |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **deleteMcpToken**
> void deleteMcpToken(deleteMcpTokenRequest)


### Example


```typescript
import { createConfiguration, McpApi } from '';
import type { McpApiDeleteMcpTokenRequest } from '';

const configuration = createConfiguration();
const apiInstance = new McpApi(configuration);

const request: McpApiDeleteMcpTokenRequest = {
  
  deleteMcpTokenRequest: {
    tokenHash: "tokenHash_example",
  },
};

const data = await apiInstance.deleteMcpToken(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deleteMcpTokenRequest** | **DeleteMcpTokenRequest**|  |


### Return type

**void**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**204** | Token revoked |  -  |
**404** | Token not found |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **getMcpTokens**
> Array<McpTokenResponse> getMcpTokens()


### Example


```typescript
import { createConfiguration, McpApi } from '';

const configuration = createConfiguration();
const apiInstance = new McpApi(configuration);

const request = {};

const data = await apiInstance.getMcpTokens(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters
This endpoint does not need any parameter.


### Return type

**Array<McpTokenResponse>**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | MCP tokens |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)


