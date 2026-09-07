# McpTokenResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**created_at** | **str** |  | 
**credential_id** | **str** |  | 
**expires_at** | **str** |  | [optional] 
**label** | **str** |  | 
**token_hash** | **str** |  | 
**workspace_id** | **str** |  | [optional] 

## Example

```python
from maskura_client.models.mcp_token_response import McpTokenResponse

# TODO update the JSON string below
json = "{}"
# create an instance of McpTokenResponse from a JSON string
mcp_token_response_instance = McpTokenResponse.from_json(json)
# print the JSON string representation of the object
print(McpTokenResponse.to_json())

# convert the object into a dict
mcp_token_response_dict = mcp_token_response_instance.to_dict()
# create an instance of McpTokenResponse from a dict
mcp_token_response_from_dict = McpTokenResponse.from_dict(mcp_token_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


