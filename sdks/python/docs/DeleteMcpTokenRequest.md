# DeleteMcpTokenRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**token_hash** | **str** |  | 

## Example

```python
from maskura_client.models.delete_mcp_token_request import DeleteMcpTokenRequest

# TODO update the JSON string below
json = "{}"
# create an instance of DeleteMcpTokenRequest from a JSON string
delete_mcp_token_request_instance = DeleteMcpTokenRequest.from_json(json)
# print the JSON string representation of the object
print(DeleteMcpTokenRequest.to_json())

# convert the object into a dict
delete_mcp_token_request_dict = delete_mcp_token_request_instance.to_dict()
# create an instance of DeleteMcpTokenRequest from a dict
delete_mcp_token_request_from_dict = DeleteMcpTokenRequest.from_dict(delete_mcp_token_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


