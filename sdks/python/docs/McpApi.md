# maskura_client.McpApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_mcp_token**](McpApi.md#create_mcp_token) | **POST** /dashboard/api/mcp-tokens | Create an MCP bearer token (&#x60;s4m_...&#x60;). The plaintext token is returned once and only its hash is stored.
[**delete_mcp_token**](McpApi.md#delete_mcp_token) | **DELETE** /dashboard/api/mcp-tokens | Revoke an MCP bearer token.
[**get_mcp_tokens**](McpApi.md#get_mcp_tokens) | **GET** /dashboard/api/mcp-tokens | List MCP bearer tokens for the authenticated user (hashes only).


# **create_mcp_token**
> McpTokenCreatedResponse create_mcp_token(create_mcp_token_request)

Create an MCP bearer token (`s4m_...`). The plaintext token is returned once and only its hash is stored.

### Example


```python
import maskura_client
from maskura_client.models.create_mcp_token_request import CreateMcpTokenRequest
from maskura_client.models.mcp_token_created_response import McpTokenCreatedResponse
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.McpApi(api_client)
    create_mcp_token_request = maskura_client.CreateMcpTokenRequest() # CreateMcpTokenRequest | 

    try:
        # Create an MCP bearer token (`s4m_...`). The plaintext token is returned once and only its hash is stored.
        api_response = api_instance.create_mcp_token(create_mcp_token_request)
        print("The response of McpApi->create_mcp_token:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling McpApi->create_mcp_token: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **create_mcp_token_request** | [**CreateMcpTokenRequest**](CreateMcpTokenRequest.md)|  | 

### Return type

[**McpTokenCreatedResponse**](McpTokenCreatedResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Created MCP token |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_mcp_token**
> delete_mcp_token(delete_mcp_token_request)

Revoke an MCP bearer token.

### Example


```python
import maskura_client
from maskura_client.models.delete_mcp_token_request import DeleteMcpTokenRequest
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.McpApi(api_client)
    delete_mcp_token_request = maskura_client.DeleteMcpTokenRequest() # DeleteMcpTokenRequest | 

    try:
        # Revoke an MCP bearer token.
        api_instance.delete_mcp_token(delete_mcp_token_request)
    except Exception as e:
        print("Exception when calling McpApi->delete_mcp_token: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **delete_mcp_token_request** | [**DeleteMcpTokenRequest**](DeleteMcpTokenRequest.md)|  | 

### Return type

void (empty response body)

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_mcp_tokens**
> List[McpTokenResponse] get_mcp_tokens()

List MCP bearer tokens for the authenticated user (hashes only).

### Example


```python
import maskura_client
from maskura_client.models.mcp_token_response import McpTokenResponse
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.McpApi(api_client)

    try:
        # List MCP bearer tokens for the authenticated user (hashes only).
        api_response = api_instance.get_mcp_tokens()
        print("The response of McpApi->get_mcp_tokens:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling McpApi->get_mcp_tokens: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[McpTokenResponse]**](McpTokenResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | MCP tokens |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

