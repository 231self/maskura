# McpTokenCreatedResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**created_at** | **str** |  | 
**credential_id** | **str** |  | 
**expires_at** | **str** |  | [optional] 
**label** | **str** |  | 
**token** | **str** |  | 
**workspace_id** | **str** |  | 

## Example

```python
from maskura_client.models.mcp_token_created_response import McpTokenCreatedResponse

# TODO update the JSON string below
json = "{}"
# create an instance of McpTokenCreatedResponse from a JSON string
mcp_token_created_response_instance = McpTokenCreatedResponse.from_json(json)
# print the JSON string representation of the object
print(McpTokenCreatedResponse.to_json())

# convert the object into a dict
mcp_token_created_response_dict = mcp_token_created_response_instance.to_dict()
# create an instance of McpTokenCreatedResponse from a dict
mcp_token_created_response_from_dict = McpTokenCreatedResponse.from_dict(mcp_token_created_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


